# hxomemo

OMEMO e2e encryption for haxe.

[XEP-0384](https://xmpp.org/extensions/attic/xep-0384-0.3.0.html) version 0.3 (`eu.siacs.conversations.axolotl`),
the one Conversations, Dino, Gajim, Monal and Profanity use: X3DH and the Double Ratchet as libsignal (version 3)
does them, devices with their bundles, sessions and the identities of other devices. The XML (device lists,
bundles, `<encrypted>`) is in [hxmpp](https://github.com/tong/hxmpp) (`xmpp.Omemo`).

```haxe
final me = omemo.Account.create();             // a new device: identity key, signed prekey, 100 prekeys
me.onChange = () -> save(me.toJson());          // the state changes with each message: store it
me.startSession("bob@example.org", 4223, bundleOfBob);
final e = me.encrypt(haxe.io.Bytes.ofString("hi"), [{jid: "bob@example.org", device: 4223}]);
// e.iv, e.payload, e.keys (one per device) go into <encrypted>
final d = me.decrypt("bob@example.org", 4223, key.data, key.preKey, iv, payload);
```

## Targets

HashLink and HashLink/C only, for now: the primitives are native (`native/omemo.c`), crypto written in Haxe would
not be constant-time. Curve25519 (X25519, XEdDSA) with [Monocypher](https://monocypher.org) 4.0.2
(`native/monocypher`, BSD-2-Clause or CC0), AES-CBC, AES-GCM, HMAC and HKDF with mbedtls 3 (bundled with HashLink).

- HashLink/C: compile `native/omemo.c` and `native/monocypher/*.c` into the program, with HashLink's mbedtls.
- HashLink: `make HASHLINK_SRC=<HashLink sources>` builds `omemo.hdll`. Built for Linux, macOS and Windows (x86_64; Linux and macOS also
  arm64, for when the HashLink VM runs there) on the [releases](https://github.com/tong/hxomemo/releases): put it next
  to `hl` or in the working directory. It needs no libhl of a particular version.

## Tests

```sh
make test HASHLINK_SRC=…                     # known vectors of the primitives, sessions and devices
python -m venv venv && venv/bin/pip install 'oldmemo[xml]'
make interop HASHLINK_SRC=…                  # with python-oldmemo: messages both ways, through its XML
```
