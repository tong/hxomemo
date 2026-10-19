package omemo;

import haxe.crypto.Base64;
import haxe.io.Bytes;
import omemo.SignalMessage;

/** The public keys of a device to start a session with (its bundle, with one of its prekeys) **/
typedef PreKeyBundle = {
	identityKey:Bytes,
	signedPreKeyId:Int,
	signedPreKey:Bytes,
	signedPreKeySignature:Bytes,
	?preKeyId:Int,
	?preKey:Bytes,
}

private typedef Chain = {key:Bytes, index:Int}
private typedef ReceiverChain = {ratchet:Bytes, chain:Chain}
private typedef SkippedKey = {ratchet:Bytes, index:Int, seed:Bytes}

/**
	A session with one device: X3DH to start it, then the Double Ratchet, as libsignal (version 3) does them.

	- X3DH: the secret of 32 bytes 0xFF and the three or four DH outputs, HKDF (salt 0, "WhisperText") to the
	  first root and chain key.
	- Root chain: HKDF (salt: the root key, "WhisperRatchet") of a DH output to the next root and chain key.
	- Message chains: HMAC of 1 for the message key seed, of 2 for the next chain key; the seed to the cipher key,
	  MAC key and IV with HKDF (salt 0, "WhisperMessageKeys").
	- Messages: AES-256-CBC, the MAC of `SignalMessage`.

	The keys of skipped messages are kept (`MAX_SKIPPED`), as are the last receiving chains, so late messages can
	still be read. A failed decryption leaves the session as it was.
**/
class Session {
	/** Messages of a chain that may be skipped at once **/
	public static inline var MAX_SKIP = 2000;

	/** The keys of skipped messages kept (the oldest are dropped) **/
	public static inline var MAX_SKIPPED = 2000;

	static inline var MAX_RECEIVER_CHAINS = 5;

	/** Our identity key (public) **/
	public var localIdentity(default, null):Bytes;

	/** The identity key of the other device **/
	public var remoteIdentity(default, null):Bytes;

	public var localRegistrationId(default, null):Int;
	public var remoteRegistrationId(default, null):Int;

	/**
		The base key of the X3DH it was built with (the initiator's ephemeral key): a `PreKeySignalMessage` with it
		belongs to this session
	**/
	public var baseKey(default, null):Bytes;

	/**
		While we started the session and the other device didn't answer yet: the keys of its bundle we used, sent
		with each message (`PreKeySignalMessage`), so it can build the session
	**/
	public var pending(default, null):Null<{preKeyId:Null<Int>, signedPreKeyId:Int}>;

	var rootKey:Bytes;
	var sendRatchet:KeyPair;
	var sendChain:Chain;
	var previousCounter:Int;
	var receiverChains:Array<ReceiverChain>;
	var skipped:Array<SkippedKey>;

	function new() {}

	/**
		Starts a session with a device from its bundle (X3DH, as initiator); throws `SessionError` if the signature
		of its signed prekey is invalid
	**/
	public static function initiate(identity:KeyPair, registrationId:Int, bundle:PreKeyBundle):Session {
		if (!Crypto.verify(bundle.identityKey, KeyPair.encode(bundle.signedPreKey), bundle.signedPreKeySignature))
			throw new SessionError("invalid signature of the signed prekey");
		final base = KeyPair.generate();
		final secret = new haxe.io.BytesBuffer();
		secret.add(filled(32, 0xff));
		secret.add(Crypto.dh(identity.priv, bundle.signedPreKey));
		secret.add(Crypto.dh(base.priv, bundle.identityKey));
		secret.add(Crypto.dh(base.priv, bundle.signedPreKey));
		if (bundle.preKey != null)
			secret.add(Crypto.dh(base.priv, bundle.preKey));
		final derived = Crypto.hkdf(secret.getBytes(), filled(32, 0), Bytes.ofString("WhisperText"), 64);
		final s = new Session();
		s.localIdentity = identity.pub;
		s.remoteIdentity = bundle.identityKey;
		s.localRegistrationId = registrationId;
		s.remoteRegistrationId = 0;
		s.baseKey = base.pub;
		s.pending = {preKeyId: bundle.preKey != null ? bundle.preKeyId : null, signedPreKeyId: bundle.signedPreKeyId};
		s.sendRatchet = KeyPair.generate();
		final next = kdfRoot(derived.sub(0, 32), Crypto.dh(s.sendRatchet.priv, bundle.signedPreKey));
		s.rootKey = next.root;
		s.sendChain = {key: next.chain, index: 0};
		s.previousCounter = 0;
		s.receiverChains = [{ratchet: bundle.signedPreKey, chain: {key: derived.sub(32, 32), index: 0}}];
		s.skipped = [];
		return s;
	}

	/**
		Builds the session another device started (X3DH, as responder), from its first message: our signed prekey
		and the prekey it used (`null` if it used none). The message itself is then read with `decrypt`.
	**/
	public static function respond(identity:KeyPair, registrationId:Int, msg:PreKeySignalMessage, signedPreKey:KeyPair, preKey:Null<KeyPair>):Session {
		final secret = new haxe.io.BytesBuffer();
		secret.add(filled(32, 0xff));
		secret.add(Crypto.dh(signedPreKey.priv, msg.identityKey));
		secret.add(Crypto.dh(identity.priv, msg.baseKey));
		secret.add(Crypto.dh(signedPreKey.priv, msg.baseKey));
		if (preKey != null)
			secret.add(Crypto.dh(preKey.priv, msg.baseKey));
		final derived = Crypto.hkdf(secret.getBytes(), filled(32, 0), Bytes.ofString("WhisperText"), 64);
		final s = new Session();
		s.localIdentity = identity.pub;
		s.remoteIdentity = msg.identityKey;
		s.localRegistrationId = registrationId;
		s.remoteRegistrationId = msg.registrationId;
		s.baseKey = msg.baseKey;
		s.pending = null;
		s.rootKey = derived.sub(0, 32);
		s.sendRatchet = signedPreKey;
		s.sendChain = {key: derived.sub(32, 32), index: 0};
		s.previousCounter = 0;
		s.receiverChains = [];
		s.skipped = [];
		return s;
	}

	/**
		Encrypts a message: a `SignalMessage`, or a `PreKeySignalMessage` (`preKey`) while the other device didn't
		answer yet
	**/
	public function encrypt(plaintext:Bytes):{data:Bytes, preKey:Bool} {
		final keys = messageKeys(chainSeed(sendChain.key));
		final ciphertext = Crypto.aesCbcEncrypt(keys.cipherKey, keys.iv, plaintext);
		final msg = SignalMessage.create(keys.macKey, sendRatchet.pub, sendChain.index, previousCounter, ciphertext, localIdentity, remoteIdentity);
		sendChain = {key: chainNext(sendChain.key), index: sendChain.index + 1};
		if (pending == null)
			return {data: msg.serialized, preKey: false};
		return {
			data: PreKeySignalMessage.create(localRegistrationId, pending.preKeyId, pending.signedPreKeyId, baseKey, localIdentity, msg).serialized,
			preKey: true
		};
	}

	/** Decrypts a message of the other device; throws `SessionError` (the session is unchanged then) **/
	public function decrypt(msg:SignalMessage):Bytes {
		final s = copy();
		final plaintext = s.decryptMessage(msg);
		assign(s);
		return plaintext;
	}

	function decryptMessage(msg:SignalMessage):Bytes {
		var receiver = null;
		for (c in receiverChains)
			if (Crypto.equals(c.ratchet, msg.ratchetKey)) {
				receiver = c;
				break;
			}
		if (receiver == null) {
			// a new ratchet key of the other side: the DH ratchet step
			final recv = kdfRoot(rootKey, Crypto.dh(sendRatchet.priv, msg.ratchetKey));
			final ratchet = KeyPair.generate();
			final send = kdfRoot(recv.root, Crypto.dh(ratchet.priv, msg.ratchetKey));
			receiver = {ratchet: msg.ratchetKey, chain: {key: recv.chain, index: 0}};
			receiverChains.push(receiver);
			if (receiverChains.length > MAX_RECEIVER_CHAINS)
				receiverChains.shift();
			rootKey = send.root;
			// as libsignal: the counter of the last message of the previous chain
			previousCounter = sendChain.index > 0 ? sendChain.index - 1 : 0;
			sendRatchet = ratchet;
			sendChain = {key: send.chain, index: 0};
		}
		final seed = messageSeed(receiver, msg.counter);
		final keys = messageKeys(seed);
		if (!msg.verifyMac(keys.macKey, remoteIdentity, localIdentity))
			throw new SessionError("invalid MAC");
		final plaintext = try Crypto.aesCbcDecrypt(keys.cipherKey, keys.iv, msg.ciphertext) catch (e) throw new SessionError("invalid ciphertext");
		// the other side answered: no prekey messages anymore
		pending = null;
		return plaintext;
	}

	/** The seed of the message key of message `counter` of a receiving chain, keeping those skipped **/
	function messageSeed(receiver:ReceiverChain, counter:Int):Bytes {
		final chain = receiver.chain;
		if (counter < chain.index) {
			for (i in 0...skipped.length) {
				final k = skipped[i];
				if (k.index == counter && Crypto.equals(k.ratchet, receiver.ratchet)) {
					skipped.splice(i, 1);
					return k.seed;
				}
			}
			throw new SessionError("message already read, or too old");
		}
		if (counter - chain.index > MAX_SKIP)
			throw new SessionError("too many skipped messages");
		var key = chain.key, index = chain.index;
		while (index < counter) {
			skipped.push({ratchet: receiver.ratchet, index: index, seed: chainSeed(key)});
			key = chainNext(key);
			index++;
		}
		if (skipped.length > MAX_SKIPPED)
			skipped.splice(0, skipped.length - MAX_SKIPPED);
		receiver.chain = {key: chainNext(key), index: index + 1};
		return chainSeed(key);
	}

	function copy():Session {
		final s = new Session();
		s.assign(this);
		s.receiverChains = [for (c in receiverChains) {ratchet: c.ratchet, chain: c.chain}];
		s.skipped = skipped.copy();
		return s;
	}

	function assign(s:Session) {
		localIdentity = s.localIdentity;
		remoteIdentity = s.remoteIdentity;
		localRegistrationId = s.localRegistrationId;
		remoteRegistrationId = s.remoteRegistrationId;
		baseKey = s.baseKey;
		pending = s.pending;
		rootKey = s.rootKey;
		sendRatchet = s.sendRatchet;
		sendChain = s.sendChain;
		previousCounter = s.previousCounter;
		receiverChains = s.receiverChains;
		skipped = s.skipped;
	}

	static function kdfRoot(rootKey:Bytes, dh:Bytes):{root:Bytes, chain:Bytes} {
		final b = Crypto.hkdf(dh, rootKey, Bytes.ofString("WhisperRatchet"), 64);
		return {root: b.sub(0, 32), chain: b.sub(32, 32)};
	}

	static inline function chainSeed(key:Bytes):Bytes
		return Crypto.hmacSha256(key, filled(1, 1));

	static inline function chainNext(key:Bytes):Bytes
		return Crypto.hmacSha256(key, filled(1, 2));

	static function messageKeys(seed:Bytes):{cipherKey:Bytes, macKey:Bytes, iv:Bytes} {
		final b = Crypto.hkdf(seed, filled(32, 0), Bytes.ofString("WhisperMessageKeys"), 80);
		return {cipherKey: b.sub(0, 32), macKey: b.sub(32, 32), iv: b.sub(64, 16)};
	}

	static function filled(len:Int, v:Int):Bytes {
		final b = Bytes.alloc(len);
		b.fill(0, len, v);
		return b;
	}

	/** The state, to store it (contains private keys) **/
	public function toJson():Dynamic {
		inline function b64(b:Bytes)
			return Base64.encode(b);
		return {
			localIdentity: b64(localIdentity),
			remoteIdentity: b64(remoteIdentity),
			localRegistrationId: localRegistrationId,
			remoteRegistrationId: remoteRegistrationId,
			baseKey: b64(baseKey),
			pending: pending,
			rootKey: b64(rootKey),
			sendRatchet: b64(sendRatchet.priv),
			sendChain: {
				key: b64(sendChain.key),
				index: sendChain.index
			},
			previousCounter: previousCounter,
			receiverChains: [
				for (c in receiverChains)
					{ratchet: b64(c.ratchet), key: b64(c.chain.key), index: c.chain.index}
			],
			skipped: [for (k in skipped) {ratchet: b64(k.ratchet), index: k.index, seed: b64(k.seed)}],
		};
	}

	public static function fromJson(o:Dynamic):Session {
		inline function b(v:Dynamic):Bytes
			return Base64.decode(v);
		final s = new Session();
		s.localIdentity = b(o.localIdentity);
		s.remoteIdentity = b(o.remoteIdentity);
		s.localRegistrationId = o.localRegistrationId;
		s.remoteRegistrationId = o.remoteRegistrationId;
		s.baseKey = b(o.baseKey);
		s.pending = o.pending;
		s.rootKey = b(o.rootKey);
		s.sendRatchet = KeyPair.ofPrivate(b(o.sendRatchet));
		s.sendChain = {key: b(o.sendChain.key), index: o.sendChain.index};
		s.previousCounter = o.previousCounter;
		s.receiverChains = [
			for (c in (o.receiverChains : Array<Dynamic>))
				{ratchet: b(c.ratchet), chain: {key: b(c.key), index: c.index}}
		];
		s.skipped = [
			for (k in (o.skipped : Array<Dynamic>)) {ratchet: b(k.ratchet), index: k.index, seed: b(k.seed)}
		];
		return s;
	}
}

class SessionError extends haxe.Exception {}
