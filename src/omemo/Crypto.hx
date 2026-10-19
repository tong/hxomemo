package omemo;

import haxe.io.Bytes;

/**
	The cryptographic primitives of OMEMO, native (`native/omemo.c`): Curve25519 with Monocypher, the symmetric
	primitives with mbedtls, random bytes from the operating system.

	Only HashLink (`omemo.hdll`) and HashLink/C (`native/omemo.c` compiled in) for now: crypto written in Haxe would
	not be constant-time. Throws `CryptoError` when a primitive fails.

	The library is optional for HashLink: a program without `omemo.hdll` still starts (see `available`), the primitives
	throw when called.
**/
class Crypto {
	static var loaded:Null<Bool>;

	/** Whether the natives are there (HashLink: `omemo.hdll` found; always with HashLink/C) **/
	public static function available():Bool {
		if (loaded == null)
			loaded = try _random(p(Bytes.alloc(1)), 1) == 0 catch (_) false;
		return loaded;
	}

	public static function random(len:Int):Bytes {
		final b = Bytes.alloc(len);
		if (_random(p(b), len) != 0)
			throw new CryptoError("no random bytes");
		return b;
	}

	/** A new X25519 key pair (the private key clamped) **/
	public static function keyPair():KeyPair {
		final priv = Bytes.alloc(32), pub = Bytes.alloc(32);
		if (_x25519_keypair(p(priv), p(pub)) != 0)
			throw new CryptoError("no random bytes");
		return new KeyPair(priv, pub);
	}

	/** The X25519 public key of the private key `priv` **/
	public static function publicKey(priv:Bytes):Bytes {
		check(priv, 32, "private key");
		final pub = Bytes.alloc(32);
		_x25519_public(p(priv), p(pub));
		return pub;
	}

	/** The X25519 shared secret of `priv` and `pub`; throws for a public key of low order **/
	public static function dh(priv:Bytes, pub:Bytes):Bytes {
		check(priv, 32, "private key");
		check(pub, 32, "public key");
		final out = Bytes.alloc(32);
		if (_x25519(p(priv), p(pub), p(out)) != 0)
			throw new CryptoError("invalid public key");
		return out;
	}

	/** XEdDSA signature (64 bytes) of `msg` with the X25519 private key `priv` **/
	public static function sign(priv:Bytes, msg:Bytes):Bytes {
		check(priv, 32, "private key");
		final sig = Bytes.alloc(64);
		if (_xeddsa_sign(p(priv), p(msg), msg.length, p(sig)) != 0)
			throw new CryptoError("no random bytes");
		return sig;
	}

	/** Whether `sig` is a signature of `msg` by the X25519 public key `pub` (XEdDSA, or older libsignal ones) **/
	public static function verify(pub:Bytes, msg:Bytes, sig:Bytes):Bool {
		if (pub.length != 32 || sig.length != 64)
			return false;
		return _xeddsa_verify(p(pub), p(msg), msg.length, p(sig));
	}

	public static function hmacSha256(key:Bytes, data:Bytes):Bytes {
		final out = Bytes.alloc(32);
		if (_hmac_sha256(p(key), key.length, p(data), data.length, p(out)) != 0)
			throw new CryptoError("hmac failed");
		return out;
	}

	/** HKDF with SHA-256 (RFC 5869): `length` bytes **/
	public static function hkdf(ikm:Bytes, salt:Bytes, info:Bytes, length:Int):Bytes {
		final out = Bytes.alloc(length);
		if (_hkdf_sha256(p(salt), salt.length, p(ikm), ikm.length, p(info), info.length, p(out), length) != 0)
			throw new CryptoError("hkdf failed");
		return out;
	}

	/** AES-256-CBC with PKCS#7 padding **/
	public static function aesCbcEncrypt(key:Bytes, iv:Bytes, plaintext:Bytes):Bytes {
		check(key, 32, "key");
		check(iv, 16, "iv");
		final out = Bytes.alloc(plaintext.length + 16);
		final len = _aes_cbc_encrypt(p(key), p(iv), p(plaintext), plaintext.length, p(out));
		if (len < 0)
			throw new CryptoError("encryption failed");
		return out.sub(0, len);
	}

	/** Decrypts AES-256-CBC with PKCS#7 padding; throws if the padding is invalid **/
	public static function aesCbcDecrypt(key:Bytes, iv:Bytes, ciphertext:Bytes):Bytes {
		check(key, 32, "key");
		check(iv, 16, "iv");
		final out = Bytes.alloc(ciphertext.length);
		final len = _aes_cbc_decrypt(p(key), p(iv), p(ciphertext), ciphertext.length, p(out));
		if (len < 0)
			throw new CryptoError("decryption failed");
		return out.sub(0, len);
	}

	/** AES-GCM with a 128 or 256 bit key: the ciphertext and the tag (16 bytes) **/
	public static function aesGcmEncrypt(key:Bytes, iv:Bytes, plaintext:Bytes):{ciphertext:Bytes, tag:Bytes} {
		final out = Bytes.alloc(plaintext.length), tag = Bytes.alloc(16);
		if (_aes_gcm_encrypt(p(key), key.length, p(iv), iv.length, p(plaintext), plaintext.length, p(out), p(tag)) != 0)
			throw new CryptoError("encryption failed");
		return {ciphertext: out, tag: tag};
	}

	/** Decrypts AES-GCM; throws if the tag (12 to 16 bytes) doesn't match **/
	public static function aesGcmDecrypt(key:Bytes, iv:Bytes, ciphertext:Bytes, tag:Bytes):Bytes {
		final out = Bytes.alloc(ciphertext.length);
		if (_aes_gcm_decrypt(p(key), key.length, p(iv), iv.length, p(ciphertext), ciphertext.length, p(tag), tag.length, p(out)) != 0)
			throw new CryptoError("decryption failed");
		return out;
	}

	/** Compares in constant time **/
	public static function equals(a:Bytes, b:Bytes):Bool
		return a.length == b.length && _equals(p(a), p(b), a.length);

	static inline function check(b:Bytes, len:Int, what:String)
		if (b.length != len)
			throw new CryptoError('$what: $len bytes expected, not ${b.length}');

	#if hl
	static inline function p(b:Bytes):hl.Bytes
		return @:privateAccess b.b;

	@:hlNative("?omemo", "random") static function _random(b:hl.Bytes, len:Int):Int
		return -1;

	@:hlNative("?omemo", "x25519_keypair") static function _x25519_keypair(priv:hl.Bytes, pub:hl.Bytes):Int
		return -1;

	@:hlNative("?omemo", "x25519_public") static function _x25519_public(priv:hl.Bytes, pub:hl.Bytes):Void {}

	@:hlNative("?omemo", "x25519") static function _x25519(priv:hl.Bytes, pub:hl.Bytes, out:hl.Bytes):Int
		return -1;

	@:hlNative("?omemo", "xeddsa_sign") static function _xeddsa_sign(priv:hl.Bytes, msg:hl.Bytes, len:Int, sig:hl.Bytes):Int
		return -1;

	@:hlNative("?omemo", "xeddsa_verify") static function _xeddsa_verify(pub:hl.Bytes, msg:hl.Bytes, len:Int, sig:hl.Bytes):Bool
		return false;

	@:hlNative("?omemo", "hmac_sha256") static function _hmac_sha256(key:hl.Bytes, keylen:Int, data:hl.Bytes, len:Int, out:hl.Bytes):Int
		return -1;

	@:hlNative("?omemo", "hkdf_sha256") static function _hkdf_sha256(salt:hl.Bytes, saltlen:Int, ikm:hl.Bytes, ikmlen:Int, info:hl.Bytes, infolen:Int,
			out:hl.Bytes, outlen:Int):Int
		return -1;

	@:hlNative("?omemo", "aes_cbc_encrypt") static function _aes_cbc_encrypt(key:hl.Bytes, iv:hl.Bytes, input:hl.Bytes, len:Int, out:hl.Bytes):Int
		return -1;

	@:hlNative("?omemo", "aes_cbc_decrypt") static function _aes_cbc_decrypt(key:hl.Bytes, iv:hl.Bytes, input:hl.Bytes, len:Int, out:hl.Bytes):Int
		return -1;

	@:hlNative("?omemo", "aes_gcm_encrypt") static function _aes_gcm_encrypt(key:hl.Bytes, keylen:Int, iv:hl.Bytes, ivlen:Int, input:hl.Bytes, len:Int,
			out:hl.Bytes, tag:hl.Bytes):Int
		return -1;

	@:hlNative("?omemo", "aes_gcm_decrypt") static function _aes_gcm_decrypt(key:hl.Bytes, keylen:Int, iv:hl.Bytes, ivlen:Int, input:hl.Bytes, len:Int,
			tag:hl.Bytes, taglen:Int, out:hl.Bytes):Int
		return -1;

	@:hlNative("?omemo", "equals") static function _equals(a:hl.Bytes, b:hl.Bytes, len:Int):Bool
		return false;
	#else
	#error "hxomemo: only HashLink and HashLink/C for now"
	#end
}

class CryptoError extends haxe.Exception {}
