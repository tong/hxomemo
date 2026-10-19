/*
        The cryptographic primitives of hxomemo (omemo.Crypto), for HashLink and
   HashLink/C.

        Curve25519 (X25519, and XEdDSA signatures with X25519 keys) with
   Monocypher (monocypher/, 4.0.2), SHA-512 for XEdDSA with its optional part.
   HMAC-SHA-256, HKDF-SHA-256, AES-CBC and AES-GCM with mbedtls 3 (the one
   bundled with HashLink). Random bytes from the operating system.

        Buffers are passed with their lengths; functions return 0 (or a length)
   on success, -1 on errors.
*/
// before hl.h, which defines _GUID (a type of DEFINE_PRIM) of windows.h
#if defined(_WIN32)
#include <windows.h>
// after windows.h (its types): not sorted with it
#include <bcrypt.h>
#endif

#define HL_NAME(n) omemo_##n
#include <hl.h>
#include <string.h>

#include "monocypher/monocypher-ed25519.h"
#include "monocypher/monocypher.h"

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#if defined(__APPLE__)
#include <stdlib.h>
#elif !defined(_WIN32)
#include <errno.h>
#include <sys/random.h>
#endif

static int fill_random(unsigned char *buf, size_t len) {
#if defined(_WIN32)
  return BCryptGenRandom(NULL, buf, (ULONG)len,
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0
             ? 0
             : -1;
#elif defined(__APPLE__)
  arc4random_buf(buf, len);
  return 0;
#else
  while (len > 0) {
    ssize_t n = getrandom(buf, len, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    buf += n;
    len -= n;
  }
  return 0;
#endif
}

HL_PRIM int HL_NAME(random)(vbyte *buf, int len) {
  return len < 0 ? -1 : fill_random(buf, len);
}

/* A new key pair: the private key clamped (as libsignal stores it, needed for
 * XEdDSA), its public key */
HL_PRIM int HL_NAME(x25519_keypair)(vbyte *priv, vbyte *pub) {
  unsigned char seed[32];
  if (fill_random(seed, 32) != 0)
    return -1;
  crypto_eddsa_trim_scalar(priv, seed);
  crypto_x25519_public_key(pub, priv);
  crypto_wipe(seed, 32);
  return 0;
}

HL_PRIM void HL_NAME(x25519_public)(vbyte *priv, vbyte *pub) {
  crypto_x25519_public_key(pub, priv);
}

/* The shared secret of `priv` and `pub`; -1 for a public key of low order (the
 * secret would be all zeros) */
HL_PRIM int HL_NAME(x25519)(vbyte *priv, vbyte *pub, vbyte *out) {
  unsigned char zero[32] = {0};
  crypto_x25519(out, priv, pub);
  return crypto_verify32(out, zero) == 0 ? -1 : 0;
}

/* L - 1, for negating a scalar (mod L) with crypto_eddsa_mul_add */
static const unsigned char L_MINUS_1[32] = {
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

/*
        XEdDSA signature (https://signal.org/docs/specifications/xeddsa/) of
   `msg` with the X25519 private key `priv`: the Edwards key pair of the scalar
   with the sign bit 0 (negated if needed), the nonce of hash1(a || M || Z) with
   64 random bytes Z, then Ed25519 (SHA-512).
*/
HL_PRIM int HL_NAME(xeddsa_sign)(vbyte *priv, vbyte *msg, int len, vbyte *sig) {
  unsigned char a[32], A[32], r[32], h[32], Z[64], hash[64], zero[32] = {0};
  static const unsigned char pad[32] = {
      0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  crypto_sha512_ctx ctx;
  if (len < 0 || fill_random(Z, 64) != 0)
    return -1;
  crypto_eddsa_trim_scalar(a, priv);
  crypto_eddsa_scalarbase(A, a);
  if (A[31] & 0x80) {
    crypto_eddsa_mul_add(a, a, L_MINUS_1, zero);
    A[31] &= 0x7f;
  }
  // r = hash1(a || M || Z) mod L
  crypto_sha512_init(&ctx);
  crypto_sha512_update(&ctx, pad, 32);
  crypto_sha512_update(&ctx, a, 32);
  crypto_sha512_update(&ctx, msg, len);
  crypto_sha512_update(&ctx, Z, 64);
  crypto_sha512_final(&ctx, hash);
  crypto_eddsa_reduce(r, hash);
  crypto_eddsa_scalarbase(sig, r);
  // h = hash(R || A || M) mod L, s = r + h a mod L
  crypto_sha512_init(&ctx);
  crypto_sha512_update(&ctx, sig, 32);
  crypto_sha512_update(&ctx, A, 32);
  crypto_sha512_update(&ctx, msg, len);
  crypto_sha512_final(&ctx, hash);
  crypto_eddsa_reduce(h, hash);
  crypto_eddsa_mul_add(sig + 32, h, a, r);
  crypto_wipe(a, 32);
  crypto_wipe(r, 32);
  crypto_wipe(hash, 64);
  return 0;
}

/*
        Verifies a signature of the X25519 public key `pub`, as libsignal does
   (curve25519_verify): the Edwards key takes its sign bit from the signature's
   last bit, which XEdDSA leaves 0. So it also accepts the signatures of older
   libsignal versions, which stored the sign bit there.
*/
HL_PRIM bool HL_NAME(xeddsa_verify)(vbyte *pub, vbyte *msg, int len,
                                    vbyte *sig) {
  unsigned char A[32], s[64], h[32], hash[64];
  crypto_sha512_ctx ctx;
  if (len < 0)
    return false;
  crypto_x25519_to_eddsa(A, pub);
  A[31] = (A[31] & 0x7f) | (sig[63] & 0x80);
  memcpy(s, sig, 64);
  s[63] &= 0x7f;
  crypto_sha512_init(&ctx);
  crypto_sha512_update(&ctx, s, 32);
  crypto_sha512_update(&ctx, A, 32);
  crypto_sha512_update(&ctx, msg, len);
  crypto_sha512_final(&ctx, hash);
  crypto_eddsa_reduce(h, hash);
  return crypto_eddsa_check_equation(s, A, h) == 0;
}

HL_PRIM int HL_NAME(hmac_sha256)(vbyte *key, int keylen, vbyte *data, int len,
                                 vbyte *out) {
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return mbedtls_md_hmac(md, key, keylen, data, len, out) == 0 ? 0 : -1;
}

HL_PRIM int HL_NAME(hkdf_sha256)(vbyte *salt, int saltlen, vbyte *ikm,
                                 int ikmlen, vbyte *info, int infolen,
                                 vbyte *out, int outlen) {
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return mbedtls_hkdf(md, salt, saltlen, ikm, ikmlen, info, infolen, out,
                      outlen) == 0
             ? 0
             : -1;
}

/* AES-256-CBC with PKCS#7 padding: `out` has room for len + 16 bytes; returns
 * the length written */
HL_PRIM int HL_NAME(aes_cbc_encrypt)(vbyte *key, vbyte *iv, vbyte *in, int len,
                                     vbyte *out) {
  mbedtls_aes_context aes;
  unsigned char v[16];
  int pad = 16 - len % 16, total = len + pad, ok;
  if (len < 0)
    return -1;
  memcpy(out, in, len);
  memset(out + len, pad, pad);
  memcpy(v, iv, 16);
  mbedtls_aes_init(&aes);
  ok =
      mbedtls_aes_setkey_enc(&aes, key, 256) == 0 &&
      mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, total, v, out, out) == 0;
  mbedtls_aes_free(&aes);
  return ok ? total : -1;
}

/* Decrypts AES-256-CBC with PKCS#7 padding: returns the length of the plaintext
 * in `out` (len bytes) */
HL_PRIM int HL_NAME(aes_cbc_decrypt)(vbyte *key, vbyte *iv, vbyte *in, int len,
                                     vbyte *out) {
  mbedtls_aes_context aes;
  unsigned char v[16];
  int ok, pad, i, bad = 0;
  if (len <= 0 || len % 16 != 0)
    return -1;
  memcpy(v, iv, 16);
  mbedtls_aes_init(&aes);
  ok = mbedtls_aes_setkey_dec(&aes, key, 256) == 0 &&
       mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, v, in, out) == 0;
  mbedtls_aes_free(&aes);
  if (!ok)
    return -1;
  // the message is authenticated before (the MAC): checking the padding in
  // constant time is not needed
  pad = out[len - 1];
  if (pad < 1 || pad > 16)
    return -1;
  for (i = 0; i < pad; i++)
    bad |= out[len - 1 - i] ^ pad;
  return bad ? -1 : len - pad;
}

/* AES-GCM (128 or 256 bit key) with a 16 byte tag */
HL_PRIM int HL_NAME(aes_gcm_encrypt)(vbyte *key, int keylen, vbyte *iv,
                                     int ivlen, vbyte *in, int len, vbyte *out,
                                     vbyte *tag) {
  mbedtls_gcm_context gcm;
  int ok;
  if (len < 0 || (keylen != 16 && keylen != 32))
    return -1;
  mbedtls_gcm_init(&gcm);
  ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, keylen * 8) == 0 &&
       mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, iv, ivlen,
                                 NULL, 0, in, out, 16, tag) == 0;
  mbedtls_gcm_free(&gcm);
  return ok ? 0 : -1;
}

/* Decrypts AES-GCM: -1 if the tag (taglen bytes, at least 12) doesn't match */
HL_PRIM int HL_NAME(aes_gcm_decrypt)(vbyte *key, int keylen, vbyte *iv,
                                     int ivlen, vbyte *in, int len, vbyte *tag,
                                     int taglen, vbyte *out) {
  mbedtls_gcm_context gcm;
  int ok;
  if (len < 0 || (keylen != 16 && keylen != 32) || taglen < 12 || taglen > 16)
    return -1;
  mbedtls_gcm_init(&gcm);
  ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, keylen * 8) == 0 &&
       mbedtls_gcm_auth_decrypt(&gcm, len, iv, ivlen, NULL, 0, tag, taglen, in,
                                out) == 0;
  mbedtls_gcm_free(&gcm);
  return ok ? 0 : -1;
}

/* Compares two buffers in constant time */
HL_PRIM bool HL_NAME(equals)(vbyte *a, vbyte *b, int len) {
  unsigned char d = 0;
  int i;
  for (i = 0; i < len; i++)
    d |= a[i] ^ b[i];
  return d == 0;
}

DEFINE_PRIM(_I32, random, _BYTES _I32);
DEFINE_PRIM(_I32, x25519_keypair, _BYTES _BYTES);
DEFINE_PRIM(_VOID, x25519_public, _BYTES _BYTES);
DEFINE_PRIM(_I32, x25519, _BYTES _BYTES _BYTES);
DEFINE_PRIM(_I32, xeddsa_sign, _BYTES _BYTES _I32 _BYTES);
DEFINE_PRIM(_BOOL, xeddsa_verify, _BYTES _BYTES _I32 _BYTES);
DEFINE_PRIM(_I32, hmac_sha256, _BYTES _I32 _BYTES _I32 _BYTES);
DEFINE_PRIM(_I32, hkdf_sha256, _BYTES _I32 _BYTES _I32 _BYTES _I32 _BYTES _I32);
DEFINE_PRIM(_I32, aes_cbc_encrypt, _BYTES _BYTES _BYTES _I32 _BYTES);
DEFINE_PRIM(_I32, aes_cbc_decrypt, _BYTES _BYTES _BYTES _I32 _BYTES);
DEFINE_PRIM(_I32, aes_gcm_encrypt,
            _BYTES _I32 _BYTES _I32 _BYTES _I32 _BYTES _BYTES);
DEFINE_PRIM(_I32, aes_gcm_decrypt,
            _BYTES _I32 _BYTES _I32 _BYTES _I32 _BYTES _I32 _BYTES);
DEFINE_PRIM(_BOOL, equals, _BYTES _BYTES _I32);
