package omemo;

import haxe.io.Bytes;
import omemo.Protobuf;

/**
	A message of a session (`SignalMessage` of libsignal, version 3): the version byte, the protobuf fields
	(ratchet key, counter, previous counter, ciphertext) and the first 8 bytes of the MAC.

	The MAC (HMAC-SHA-256 with the message's MAC key) covers the encoded identity keys of the sender and of the
	receiver, the version and the fields.
**/
class SignalMessage {
	public static inline var VERSION = 3;
	static inline var MAC_LENGTH = 8;

	public final ratchetKey:Bytes;
	public final counter:Int;
	public final previousCounter:Int;
	public final ciphertext:Bytes;

	/** As sent **/
	public final serialized:Bytes;

	function new(ratchetKey, counter, previousCounter, ciphertext, serialized) {
		this.ratchetKey = ratchetKey;
		this.counter = counter;
		this.previousCounter = previousCounter;
		this.ciphertext = ciphertext;
		this.serialized = serialized;
	}

	public static function create(macKey:Bytes, ratchetKey:Bytes, counter:Int, previousCounter:Int, ciphertext:Bytes, senderIdentity:Bytes,
			receiverIdentity:Bytes):SignalMessage {
		final fields = new ProtobufWriter().bytes(1, KeyPair.encode(ratchetKey))
			.int(2, counter)
			.int(3, previousCounter)
			.bytes(4, ciphertext)
			.getBytes();
		final msg = Bytes.alloc(1 + fields.length + MAC_LENGTH);
		msg.set(0, (VERSION << 4) | VERSION);
		msg.blit(1, fields, 0, fields.length);
		final mac = computeMac(macKey, senderIdentity, receiverIdentity, msg, 1 + fields.length);
		msg.blit(1 + fields.length, mac, 0, MAC_LENGTH);
		return new SignalMessage(ratchetKey, counter, previousCounter, ciphertext, msg);
	}

	/** Throws `MessageError` if it isn't a message of version 3 **/
	public static function parse(b:Bytes):SignalMessage {
		if (b.length < 1 + MAC_LENGTH)
			throw new MessageError("message too short");
		checkVersion(b.get(0));
		final fields = try Protobuf.parse(b, 1, b.length - 1 - MAC_LENGTH) catch (e:ProtobufError) throw new MessageError(e.message);
		final ratchetKey = Protobuf.bytes(fields, 1), counter = Protobuf.int(fields, 2), ciphertext = Protobuf.bytes(fields, 4);
		if (ratchetKey == null || counter == null || ciphertext == null)
			throw new MessageError("incomplete message");
		final key = try KeyPair.decode(ratchetKey) catch (e) throw new MessageError("invalid ratchet key");
		return new SignalMessage(key, counter, Protobuf.int(fields, 3) ?? 0, ciphertext, b);
	}

	public function verifyMac(macKey:Bytes, senderIdentity:Bytes, receiverIdentity:Bytes):Bool {
		final len = serialized.length - MAC_LENGTH;
		final mac = computeMac(macKey, senderIdentity, receiverIdentity, serialized, len).sub(0, MAC_LENGTH);
		return Crypto.equals(mac, serialized.sub(len, MAC_LENGTH));
	}

	static function computeMac(macKey:Bytes, senderIdentity:Bytes, receiverIdentity:Bytes, msg:Bytes, len:Int):Bytes {
		final data = Bytes.alloc(66 + len);
		data.blit(0, KeyPair.encode(senderIdentity), 0, 33);
		data.blit(33, KeyPair.encode(receiverIdentity), 0, 33);
		data.blit(66, msg, 0, len);
		return Crypto.hmacSha256(macKey, data);
	}

	public static function checkVersion(v:Int)
		if (v >> 4 != VERSION)
			throw new MessageError('unsupported version ${v >> 4}');
}

/**
	The first messages of a session, until the other side answered (`PreKeySignalMessage` of libsignal): what the
	receiver needs to build the session (the keys of its bundle used, the sender's identity and base key), and the
	message.
**/
class PreKeySignalMessage {
	public final registrationId:Int;
	public final preKeyId:Null<Int>;
	public final signedPreKeyId:Int;
	public final baseKey:Bytes;
	public final identityKey:Bytes;
	public final message:SignalMessage;
	public final serialized:Bytes;

	function new(registrationId, preKeyId, signedPreKeyId, baseKey, identityKey, message, serialized) {
		this.registrationId = registrationId;
		this.preKeyId = preKeyId;
		this.signedPreKeyId = signedPreKeyId;
		this.baseKey = baseKey;
		this.identityKey = identityKey;
		this.message = message;
		this.serialized = serialized;
	}

	public static function create(registrationId:Int, preKeyId:Null<Int>, signedPreKeyId:Int, baseKey:Bytes, identityKey:Bytes,
			message:SignalMessage):PreKeySignalMessage {
		final w = new ProtobufWriter();
		if (preKeyId != null)
			w.int(1, preKeyId);
		w.bytes(2, KeyPair.encode(baseKey))
			.bytes(3, KeyPair.encode(identityKey))
			.bytes(4, message.serialized)
			.int(5, registrationId)
			.int(6, signedPreKeyId);
		final fields = w.getBytes();
		final b = Bytes.alloc(1 + fields.length);
		b.set(0, (SignalMessage.VERSION << 4) | SignalMessage.VERSION);
		b.blit(1, fields, 0, fields.length);
		return new PreKeySignalMessage(registrationId, preKeyId, signedPreKeyId, baseKey, identityKey, message, b);
	}

	public static function parse(b:Bytes):PreKeySignalMessage {
		if (b.length < 2)
			throw new MessageError("message too short");
		SignalMessage.checkVersion(b.get(0));
		final fields = try Protobuf.parse(b, 1) catch (e:ProtobufError) throw new MessageError(e.message);
		final signedPreKeyId = Protobuf.int(fields,
			6), baseKey = Protobuf.bytes(fields, 2), identityKey = Protobuf.bytes(fields, 3), message = Protobuf.bytes(fields, 4);
		if (signedPreKeyId == null || baseKey == null || identityKey == null || message == null)
			throw new MessageError("incomplete message");
		final base = try KeyPair.decode(baseKey) catch (e) throw new MessageError("invalid base key");
		final identity = try KeyPair.decode(identityKey) catch (e) throw new MessageError("invalid identity key");
		return new PreKeySignalMessage(Protobuf.int(fields, 5) ?? 0, Protobuf.int(fields, 1), signedPreKeyId, base, identity, SignalMessage.parse(message), b);
	}
}

class MessageError extends haxe.Exception {}
