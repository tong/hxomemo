package omemo;

import haxe.io.Bytes;

/** An X25519 key pair (32 bytes each) **/
class KeyPair {
	public final priv:Bytes;
	public final pub:Bytes;

	public function new(priv:Bytes, pub:Bytes) {
		this.priv = priv;
		this.pub = pub;
	}

	public static inline function generate():KeyPair
		return Crypto.keyPair();

	/** The key pair of the private key `priv` **/
	public static function ofPrivate(priv:Bytes):KeyPair
		return new KeyPair(priv, Crypto.publicKey(priv));

	/** The public key in the encoding of libsignal: the type 5 (Curve25519) and the key **/
	public static function encode(pub:Bytes):Bytes {
		final b = Bytes.alloc(33);
		b.set(0, 5);
		b.blit(1, pub, 0, 32);
		return b;
	}

	/** The key of an encoded public key; throws if it isn't one **/
	public static function decode(b:Null<Bytes>):Bytes {
		// some clients publish keys without the type
		if (b != null && b.length == 32)
			return b;
		if (b == null || b.length != 33 || b.get(0) != 5)
			throw new Crypto.CryptoError("invalid public key");
		return b.sub(1, 32);
	}

	/**
		The fingerprint of a public (identity) key as other clients show it: the key in hex, in groups of 8
		(Conversations, Dino, Gajim)
	**/
	public static function fingerprint(pub:Bytes):String {
		final hex = pub.toHex();
		return [for (i in 0...Std.int(hex.length / 8)) hex.substr(i * 8, 8)].join(" ");
	}
}
