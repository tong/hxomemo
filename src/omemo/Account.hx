package omemo;

import haxe.crypto.Base64;
import haxe.io.Bytes;
import omemo.Session;
import omemo.SignalMessage;

/** The public part of our device: what is published as bundle **/
typedef Bundle = {
	identityKey:Bytes,
	signedPreKeyId:Int,
	signedPreKey:Bytes,
	signedPreKeySignature:Bytes,
	preKeys:Array<{id:Int, key:Bytes}>,
}

/** A message encrypted for devices: the payload once, its key for each device **/
typedef Encrypted = {
	iv:Bytes,

	/** `null` for an empty message (only the keys, e.g. to answer a new session) **/
	payload:Null<Bytes>,

	keys:Array<{
		jid:String,
		device:Int,
		data:Bytes,
		preKey:Bool
	}>,

	/** The devices without a session: they can't read it **/
	missing:Array<{jid:String, device:Int}>,
}

typedef Decrypted = {
	/** `null` for an empty message **/
	plaintext:Null<Bytes>,

	/** The message started a new session (the sender used our bundle) **/
	newSession:Bool,

	/** A prekey of the bundle was used: publish the bundle with a new one (`refillPreKeys`) **/
	preKeyUsed:Bool,
}

enum abstract Trust(String) to String {
	/** Not decided yet (seen for the first time) **/
	var Undecided = "undecided";

	var Trusted = "trusted";

	/** Compared with the other device (e.g. the fingerprint or a QR code) **/
	var Verified = "verified";

	var Untrusted = "untrusted";
}

typedef Identity = {key:Bytes, trust:Trust}
private typedef SignedPreKey = {id:Int, pair:KeyPair, signature:Bytes, created:Float}

/**
	An OMEMO device of an account (version 0.3, `eu.siacs.conversations.axolotl`): its keys, the bundle, the sessions
	with the devices of contacts and the own other ones, and the identity keys seen of them.

	Messages: the payload is encrypted once with AES-128-GCM, its key and tag (the key material, 32 bytes) for each
	device with the session. The state changes with each message: store it (`toJson`) when `onChange` is called.
**/
class Account {
	/** Prekeys in the bundle **/
	public static inline var PREKEYS = 100;

	/** Previous sessions of a device kept, for messages of the other side using one of them still **/
	static inline var PREVIOUS_SESSIONS = 10;

	static inline var MAX_PREKEY_ID = 0xffffff;

	public var deviceId(default, null):Int;
	public var registrationId(default, null):Int;
	public var identity(default, null):KeyPair;

	/** Called when the state changed (a new session, a message, prekeys): store it **/
	public var onChange:() -> Void = () -> {};

	var signedPreKey:SignedPreKey;
	var previousSignedPreKey:Null<SignedPreKey>;
	var preKeys:Map<Int, KeyPair>;
	var nextPreKeyId:Int;
	var sessions:Map<String, Map<Int, Array<Session>>>;
	var identities:Map<String, Map<Int, Identity>>;

	function new() {}

	/** A new device: identity key, signed prekey, prekeys; the device id random, if not given **/
	public static function create(?deviceId:Int):Account {
		final a = new Account();
		a.deviceId = deviceId ?? randomInt(0x7fffffff);
		a.registrationId = randomInt(16380);
		a.identity = KeyPair.generate();
		a.preKeys = [];
		a.nextPreKeyId = randomInt(MAX_PREKEY_ID);
		a.sessions = [];
		a.identities = [];
		a.signedPreKey = a.newSignedPreKey(randomInt(MAX_PREKEY_ID));
		a.previousSignedPreKey = null;
		a.refillPreKeys();
		return a;
	}

	/** A random number from 1 to `max` **/
	static function randomInt(max:Int):Int {
		final b = Crypto.random(4);
		final v = (b.get(0) | (b.get(1) << 8) | (b.get(2) << 16) | ((b.get(3) & 0x7f) << 24));
		return 1 + v % max;
	}

	function newSignedPreKey(id:Int):SignedPreKey {
		final pair = KeyPair.generate();
		return {
			id: id,
			pair: pair,
			signature: Crypto.sign(identity.priv, KeyPair.encode(pair.pub)),
			created: Date.now().getTime()
		};
	}

	/** Adds prekeys up to `PREKEYS`; whether it added any (publish the bundle then) **/
	public function refillPreKeys():Bool {
		var added = false;
		while (Lambda.count(preKeys) < PREKEYS) {
			preKeys.set(nextPreKeyId, KeyPair.generate());
			nextPreKeyId = nextPreKeyId % MAX_PREKEY_ID + 1;
			added = true;
		}
		if (added)
			onChange();
		return added;
	}

	/**
		A new signed prekey (publish the bundle then); the previous one is kept, for sessions started with it
		before the new bundle was seen
	**/
	public function rotateSignedPreKey() {
		previousSignedPreKey = signedPreKey;
		signedPreKey = newSignedPreKey(signedPreKey.id % MAX_PREKEY_ID + 1);
		onChange();
	}

	/** When the signed prekey was created (ms since 1970) **/
	public function signedPreKeyCreated():Float
		return signedPreKey.created;

	public function bundle():Bundle
		return {
			identityKey: identity.pub,
			signedPreKeyId: signedPreKey.id,
			signedPreKey: signedPreKey.pair.pub,
			signedPreKeySignature: signedPreKey.signature,
			preKeys: [
				for (id => k in preKeys) {
					id: id,
					key: k.pub
				}
			],
		};

	/** The fingerprint of our identity key **/
	public function fingerprint():String
		return KeyPair.fingerprint(identity.pub);

	public function hasSession(jid:String, device:Int):Bool
		return sessions.get(jid)?.exists(device) ?? false;

	/**
		Starts a session with a device from its bundle and one of its prekeys (X3DH); throws `SessionError` for an
		invalid bundle, `IdentityError` if the device has another identity key than seen before.
	**/
	public function startSession(jid:String, device:Int, bundle:PreKeyBundle) {
		checkIdentity(jid, device, bundle.identityKey);
		addSession(jid, device, Session.initiate(identity, registrationId, bundle));
		addIdentity(jid, device, bundle.identityKey);
		onChange();
	}

	/**
		Encrypts a message for devices (those of the contact and our other ones), `null` for an empty one: with the
		sessions there are (see `missing`)
	**/
	public function encrypt(plaintext:Null<Bytes>, devices:Array<{jid:String, device:Int}>):Encrypted {
		final key = Crypto.random(16), iv = Crypto.random(12);
		var payload = null, material = key;
		if (plaintext != null) {
			final e = Crypto.aesGcmEncrypt(key, iv, plaintext);
			payload = e.ciphertext;
			material = Bytes.alloc(32);
			material.blit(0, key, 0, 16);
			material.blit(16, e.tag, 0, 16);
		}
		final keys = [], missing = [];
		for (d in devices) {
			final record = sessions.get(d.jid)?.get(d.device);
			final s = record != null ? record[0] : null;
			if (s == null) {
				missing.push(d);
				continue;
			}
			final m = s.encrypt(material);
			keys.push({
				jid: d.jid,
				device: d.device,
				data: m.data,
				preKey: m.preKey
			});
		}
		if (keys.length > 0)
			onChange();
		return {
			iv: iv,
			payload: payload,
			keys: keys,
			missing: missing
		};
	}

	/**
		Decrypts a message of a device: its key for us (`data`, a `PreKeySignalMessage` if `preKey`), the IV and
		the payload (`null` for an empty message). Throws `SessionError`, `MessageError`, `IdentityError` or
		`CryptoError` (a payload not matching its key); the state is unchanged then, except for a payload not
		matching its key (the key was read).
	**/
	public function decrypt(jid:String, device:Int, data:Bytes, preKey:Bool, iv:Bytes, payload:Null<Bytes>):Decrypted {
		var material:Bytes, newSession = false, preKeyUsed = false;
		if (preKey) {
			final msg = PreKeySignalMessage.parse(data);
			checkIdentity(jid, device, msg.identityKey);
			final existing = [
				for (s in sessions.get(jid)?.get(device) ?? []) if (Crypto.equals(s.baseKey, msg.baseKey)) s
			];
			if (existing.length > 0) {
				// another message of a session already built
				material = existing[0].decrypt(msg.message);
				addSession(jid, device, existing[0]);
			} else {
				final spk = if (signedPreKey.id == msg.signedPreKeyId) signedPreKey else if (previousSignedPreKey?.id == msg.signedPreKeyId)
					previousSignedPreKey else throw new SessionError('unknown signed prekey ${msg.signedPreKeyId}');
				final pk = msg.preKeyId != null ? preKeys.get(msg.preKeyId) : null;
				if (msg.preKeyId != null && pk == null)
					throw new SessionError('unknown prekey ${msg.preKeyId} (used already)');
				final s = Session.respond(identity, registrationId, msg, spk.pair, pk);
				material = s.decrypt(msg.message);
				addSession(jid, device, s);
				addIdentity(jid, device, msg.identityKey);
				if (msg.preKeyId != null) {
					preKeys.remove(msg.preKeyId);
					preKeyUsed = true;
				}
				newSession = true;
			}
		} else {
			final msg = SignalMessage.parse(data);
			final record = sessions.get(jid)?.get(device);
			if (record == null)
				throw new SessionError('no session with $jid/$device');
			material = null;
			for (s in record)
				try {
					material = s.decrypt(msg);
					addSession(jid, device, s);
					break;
				} catch (e:SessionError) {
					if (s == record[record.length - 1])
						throw e;
				}
		}
		onChange();
		return {plaintext: payload == null ? null : decryptPayload(material, iv, payload), newSession: newSession, preKeyUsed: preKeyUsed};
	}

	/** The payload: key and tag in the key material (32 bytes), or the tag at the end of the payload (16) **/
	static function decryptPayload(material:Bytes, iv:Bytes, payload:Bytes):Bytes {
		if (material.length >= 32)
			return Crypto.aesGcmDecrypt(material.sub(0, 16), iv, payload, material.sub(16, 16));
		if (material.length == 16 && payload.length >= 16)
			return Crypto.aesGcmDecrypt(material, iv, payload.sub(0, payload.length - 16), payload.sub(payload.length - 16, 16));
		throw new Crypto.CryptoError("invalid key");
	}

	/** Makes `s` the current session of the device, keeping the previous ones **/
	function addSession(jid:String, device:Int, s:Session) {
		var devices = sessions.get(jid);
		if (devices == null)
			sessions.set(jid, devices = []);
		final record = (devices.get(device) ?? []).filter(o -> o != s);
		record.unshift(s);
		if (record.length > 1 + PREVIOUS_SESSIONS)
			record.resize(1 + PREVIOUS_SESSIONS);
		devices.set(device, record);
	}

	function checkIdentity(jid:String, device:Int, key:Bytes) {
		final known = identities.get(jid)?.get(device);
		if (known != null && !Crypto.equals(known.key, key))
			throw new IdentityError(jid, device, key);
	}

	function addIdentity(jid:String, device:Int, key:Bytes) {
		var devices = identities.get(jid);
		if (devices == null)
			identities.set(jid, devices = []);
		if (!devices.exists(device))
			devices.set(device, {key: key, trust: Undecided});
	}

	/** The identity keys seen of the devices of `jid` **/
	public function identitiesOf(jid:String):Map<Int, Identity>
		return identities.get(jid) ?? [];

	public function identityOf(jid:String, device:Int):Null<Identity>
		return identities.get(jid)?.get(device);

	public function setTrust(jid:String, device:Int, trust:Trust) {
		final i = identities.get(jid)?.get(device);
		if (i != null && i.trust != trust) {
			i.trust = trust;
			onChange();
		}
	}

	/**
		Forgets a device: its sessions and identity key (e.g. after it was reinstalled with a new key, see
		`IdentityError`)
	**/
	public function forget(jid:String, device:Int) {
		sessions.get(jid)?.remove(device);
		identities.get(jid)?.remove(device);
		onChange();
	}

	public function toJson():Dynamic {
		inline function b64(b:Bytes)
			return Base64.encode(b);
		function spk(k:Null<SignedPreKey>):Dynamic
			return k == null ? null : {
				id: k.id,
				priv: b64(k.pair.priv),
				signature: b64(k.signature),
				created: k.created
			};
		return {
			version: 1,
			deviceId: deviceId,
			registrationId: registrationId,
			identity: b64(identity.priv),
			signedPreKey: spk(signedPreKey),
			previousSignedPreKey: spk(previousSignedPreKey),
			preKeys: [
				for (id => k in preKeys) {
					id: id,
					priv: b64(k.priv)
				}
			],
			nextPreKeyId: nextPreKeyId,
			sessions: [
				for (jid => devices in sessions)
					for (device => record in devices)
						{jid: jid, device: device, sessions: [for (s in record) s.toJson()]}
			],
			identities: [
				for (jid => devices in identities)
					for (device => i in devices)
						{
							jid: jid,
							device: device,
							key: b64(i.key),
							trust: (i.trust : String)
						}
			],
		};
	}

	public static function fromJson(o:Dynamic):Account {
		inline function b(v:Dynamic):Bytes
			return Base64.decode(v);
		function spk(k:Dynamic):Null<SignedPreKey>
			return k == null ? null : {
				id: k.id,
				pair: KeyPair.ofPrivate(b(k.priv)),
				signature: b(k.signature),
				created: k.created
			};
		final a = new Account();
		a.deviceId = o.deviceId;
		a.registrationId = o.registrationId;
		a.identity = KeyPair.ofPrivate(b(o.identity));
		a.signedPreKey = spk(o.signedPreKey);
		a.previousSignedPreKey = spk(o.previousSignedPreKey);
		a.preKeys = [
			for (k in (o.preKeys : Array<Dynamic>)) (k.id : Int) => KeyPair.ofPrivate(b(k.priv))
		];
		a.nextPreKeyId = o.nextPreKeyId;
		a.sessions = [];
		for (r in (o.sessions : Array<Dynamic>)) {
			var devices = a.sessions.get(r.jid);
			if (devices == null)
				a.sessions.set(r.jid, devices = []);
			devices.set(r.device, [for (s in (r.sessions : Array<Dynamic>)) Session.fromJson(s)]);
		}
		a.identities = [];
		for (i in (o.identities : Array<Dynamic>)) {
			var devices = a.identities.get(i.jid);
			if (devices == null)
				a.identities.set(i.jid, devices = []);
			devices.set(i.device, {key: b(i.key), trust: (i.trust : Trust)});
		}
		return a;
	}
}

/** A device sent another identity key than seen before **/
class IdentityError extends haxe.Exception {
	public final jid:String;
	public final device:Int;
	public final key:Bytes;

	public function new(jid:String, device:Int, key:Bytes) {
		super('$jid/$device: another identity key than before');
		this.jid = jid;
		this.device = device;
		this.key = key;
	}
}
