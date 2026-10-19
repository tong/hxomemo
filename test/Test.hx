import haxe.io.Bytes;
import omemo.Account;
import omemo.Crypto;
import omemo.KeyPair;
import omemo.Session;

/** Tests of hxomemo: the primitives with known vectors, sessions and accounts with each other **/
class Test {
	static var failed = 0;
	static var passed = 0;

	static function main() {
		primitives();
		signatures();
		sessions();
		accounts();
		Sys.println('$passed passed, $failed failed');
		Sys.exit(failed > 0 ? 1 : 0);
	}

	static function check(ok:Bool, what:String, ?pos:haxe.PosInfos) {
		if (ok)
			passed++;
		else {
			failed++;
			Sys.println('FAIL ${pos.lineNumber}: $what');
		}
	}

	static function equals(a:Bytes, b:Bytes, what:String, ?pos:haxe.PosInfos)
		check(a.compare(b) == 0, '$what: ${a.toHex()} != ${b.toHex()}', pos);

	static function throws(f:() -> Void, what:String, ?pos:haxe.PosInfos) {
		var thrown = false;
		try
			f()
		catch (e)
			thrown = true;
		check(thrown, '$what: no error', pos);
	}

	static inline function hex(s:String):Bytes
		return Bytes.ofHex(s);

	static function primitives() {
		// RFC 7748 6.1
		final a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
		final b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
		equals(Crypto.publicKey(a), hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), "x25519 public");
		equals(Crypto.dh(a, Crypto.publicKey(b)), hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"), "x25519");
		throws(() -> Crypto.dh(a, Bytes.alloc(32)), "x25519 with a low order point");
		// RFC 5869 A.1
		equals(Crypto.hkdf(hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), hex("000102030405060708090a0b0c"), hex("f0f1f2f3f4f5f6f7f8f9"), 42),
			hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), "hkdf");
		// RFC 4231 2
		equals(Crypto.hmacSha256(Bytes.ofString("Jefe"), Bytes.ofString("what do ya want for nothing?")),
			hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), "hmac");
		// GCM spec, test case 3
		final k = hex("feffe9928665731c6d6a8f9467308308"), iv = hex("cafebabefacedbaddecaf888");
		final p = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
		final e = Crypto.aesGcmEncrypt(k, iv, p);
		equals(e.ciphertext,
			hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"), "gcm");
		equals(e.tag, hex("4d5c2af327cd64a62cf35abd2ba6fab4"), "gcm tag");
		equals(Crypto.aesGcmDecrypt(k, iv, e.ciphertext, e.tag), p, "gcm decrypt");
		final bad = e.tag.sub(0, 16);
		bad.set(0, bad.get(0) ^ 1);
		throws(() -> Crypto.aesGcmDecrypt(k, iv, e.ciphertext, bad), "gcm with a wrong tag");
		// CBC: padding of all lengths
		final key = Crypto.random(32), iv16 = Crypto.random(16);
		for (n in [0, 1, 15, 16, 17, 100]) {
			final m = Crypto.random(n);
			final c = Crypto.aesCbcEncrypt(key, iv16, m);
			check(c.length == (Std.int(n / 16) + 1) * 16, 'cbc length $n');
			equals(Crypto.aesCbcDecrypt(key, iv16, c), m, 'cbc $n');
		}
		throws(() -> Crypto.aesCbcDecrypt(Crypto.random(32), iv16, Crypto.aesCbcEncrypt(key, iv16, Bytes.ofString("x"))), "cbc with a wrong key");
	}

	static function signatures() {
		for (i in 0...20) {
			final k = KeyPair.generate();
			final m = Crypto.random(i * 7);
			final sig = Crypto.sign(k.priv, m);
			check(Crypto.verify(k.pub, m, sig), "xeddsa");
			check(sig.get(63) & 0x80 == 0, "xeddsa: sign bit 0");
			final changed = m.length > 0 ? m.sub(0, m.length) : Bytes.ofString("x");
			changed.set(0, changed.get(0) ^ 1);
			check(!Crypto.verify(k.pub, changed, sig), "xeddsa: other message");
			check(!Crypto.verify(KeyPair.generate().pub, m, sig), "xeddsa: other key");
		}
	}

	static function bundleOf(a:Account, ?preKey = true):PreKeyBundle {
		final b = a.bundle();
		return {
			identityKey: b.identityKey,
			signedPreKeyId: b.signedPreKeyId,
			signedPreKey: b.signedPreKey,
			signedPreKeySignature: b.signedPreKeySignature,
			preKeyId: preKey ? b.preKeys[0].id : null,
			preKey: preKey ? b.preKeys[0].key : null,
		};
	}

	static function send(from:Account, fromJid:String, to:Account, toJid:String, text:Null<String>) {
		final e = from.encrypt(text == null ? null : Bytes.ofString(text), [{jid: toJid, device: to.deviceId}]);
		final k = e.keys[0];
		return {
			preKey: k.preKey,
			read: () -> to.decrypt(fromJid, from.deviceId, k.data, k.preKey, e.iv, e.payload)
		};
	}

	static function text(d:Decrypted):Null<String>
		return d.plaintext?.toString();

	static function sessions() {
		final alice = Account.create(), bob = Account.create();
		alice.startSession("bob@example.org", bob.deviceId, bundleOf(bob));
		final m1 = send(alice, "alice@example.org", bob, "bob@example.org", "hello");
		final m2 = send(alice, "alice@example.org", bob, "bob@example.org", "second");
		check(m1.preKey && m2.preKey, "prekey messages before an answer");
		final d1 = m1.read();
		check(text(d1) == "hello" && d1.newSession && d1.preKeyUsed, "first message");
		final d2 = m2.read();
		check(text(d2) == "second" && !d2.newSession, "second prekey message: the same session");
		throws(() -> m1.read(), "a message read twice");
		final r = send(bob, "bob@example.org", alice, "alice@example.org", "hi alice");
		check(!r.preKey, "the answer is no prekey message");
		check(text(r.read()) == "hi alice", "answer");
		final m3 = send(alice, "alice@example.org", bob, "bob@example.org", "after the answer");
		check(!m3.preKey, "no prekey message after the answer");
		check(text(m3.read()) == "after the answer", "message after the answer");

		// out of order, over several ratchet steps
		final queue = [for (i in 0...5) send(alice, "alice@example.org", bob, "bob@example.org", 'a$i')];
		check(text(queue[3].read()) == "a3", "skipped messages");
		check(text(queue[0].read()) == "a0", "a skipped message");
		final b1 = send(bob, "bob@example.org", alice, "alice@example.org", "b1");
		check(text(b1.read()) == "b1", "answer after skipping");
		final late = send(alice, "alice@example.org", bob, "bob@example.org", "new chain");
		check(text(queue[4].read()) == "a4", "a message of the previous chain");
		check(text(queue[1].read()) == "a1" && text(queue[2].read()) == "a2", "the other skipped ones");
		check(text(late.read()) == "new chain", "the new chain");

		// an empty message (key transport)
		final empty = send(bob, "bob@example.org", alice, "alice@example.org", null);
		check(empty.read().plaintext == null, "empty message");

		// a forged message leaves the session as it was
		final e = alice.encrypt(Bytes.ofString("x"), [{jid: "bob@example.org", device: bob.deviceId}]);
		final forged = e.keys[0].data.sub(0, e.keys[0].data.length);
		forged.set(forged.length - 1, forged.get(forged.length - 1) ^ 1);
		throws(() -> bob.decrypt("alice@example.org", alice.deviceId, forged, false, e.iv, e.payload), "forged MAC");
		check(bob.decrypt("alice@example.org", alice.deviceId, e.keys[0].data, false, e.iv, e.payload).plaintext.toString() == "x",
			"the message after a forged one");

		// without prekey (all used)
		final carol = Account.create();
		carol.startSession("bob@example.org", bob.deviceId, bundleOf(bob, false));
		final c = send(carol, "carol@example.org", bob, "bob@example.org", "no prekey");
		check(text(c.read()) == "no prekey", "session without prekey");

		// both start a session at the same time
		final dave = Account.create(), erin = Account.create();
		dave.startSession("erin@example.org", erin.deviceId, bundleOf(erin));
		erin.startSession("dave@example.org", dave.deviceId, bundleOf(dave));
		final de = send(dave, "dave@example.org", erin, "erin@example.org", "from dave");
		final ed = send(erin, "erin@example.org", dave, "dave@example.org", "from erin");
		check(text(de.read()) == "from dave" && text(ed.read()) == "from erin", "sessions started by both");
		final de2 = send(dave, "dave@example.org", erin, "erin@example.org", "dave again");
		final ed2 = send(erin, "erin@example.org", dave, "dave@example.org", "erin again");
		check(text(de2.read()) == "dave again" && text(ed2.read()) == "erin again", "messages after both started");
	}

	static function accounts() {
		final alice = Account.create(), bob = Account.create();
		final b = alice.bundle();
		check(b.preKeys.length == Account.PREKEYS, "prekeys");
		check(Crypto.verify(b.identityKey, KeyPair.encode(b.signedPreKey), b.signedPreKeySignature), "signed prekey");
		alice.startSession("bob@example.org", bob.deviceId, bundleOf(bob));
		send(alice, "alice@example.org", bob, "bob@example.org", "one").read();
		check(bob.refillPreKeys() && bob.bundle().preKeys.length == Account.PREKEYS, "prekeys refilled");

		// stored and loaded, both
		final alice2 = Account.fromJson(haxe.Json.parse(haxe.Json.stringify(alice.toJson())));
		final bob2 = Account.fromJson(haxe.Json.parse(haxe.Json.stringify(bob.toJson())));
		check(text(send(bob2, "bob@example.org", alice2, "alice@example.org", "loaded").read()) == "loaded", "loaded accounts");
		check(text(send(alice2, "alice@example.org", bob2, "bob@example.org", "loaded too").read()) == "loaded too", "loaded accounts, back");
		check(alice2.fingerprint() == alice.fingerprint() && alice2.deviceId == alice.deviceId, "loaded identity");

		// another identity key for a device seen before
		final mallory = Account.create(bob.deviceId);
		throws(() -> alice.startSession("bob@example.org", bob.deviceId, bundleOf(mallory)), "another identity key");
		check(bob.identityOf("alice@example.org", alice.deviceId)?.trust == Undecided, "identity seen");

		// an invalid bundle signature
		final forged = bundleOf(Account.create());
		forged.signedPreKey = KeyPair.generate().pub;
		throws(() -> Account.create().startSession("x@example.org", 1, forged), "invalid signature");

		// rotated signed prekey: sessions started with the previous one still work
		final frank = Account.create(), grace = Account.create();
		final old = bundleOf(grace);
		grace.rotateSignedPreKey();
		frank.startSession("grace@example.org", grace.deviceId, old);
		check(text(send(frank, "frank@example.org", grace, "grace@example.org", "old spk").read()) == "old spk", "previous signed prekey");
	}
}
