"""
hxomemo with python-oldmemo (Syndace's OMEMO 0.3, compatible with libsignal): sessions started by both sides,
messages both ways, out of order, empty messages. Bundles and messages go through oldmemo's XML (etree).

    python -m venv venv && venv/bin/pip install oldmemo
    venv/bin/python -I test/interop.py hl test/peer.hl
"""

import asyncio
import base64
import json
import random
import subprocess
import sys
import xml.etree.ElementTree as ET

from oldmemo import etree, oldmemo
from omemo.message import Message
from omemo.storage import Just, Nothing, Storage

NS = "{eu.siacs.conversations.axolotl}"
PY_JID, PY_DEVICE = "python@example.org", 31415
HX_JID = "haxe@example.org"

b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode
failures = 0


def check(ok, what):
    global failures
    if not ok:
        failures += 1
    print(("ok   " if ok else "FAIL ") + what)


class MemoryStorage(Storage):
    def __init__(self):
        super().__init__(True)
        self.data = {}

    async def _load(self, key):
        return Just(self.data[key]) if key in self.data else Nothing()

    async def _store(self, key, value):
        self.data[key] = value

    async def _delete(self, key):
        self.data.pop(key, None)


class Peer:
    def __init__(self, cmd):
        self.p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )

    def __call__(self, **c):
        self.p.stdin.write(json.dumps(c) + "\n")
        self.p.stdin.flush()
        r = json.loads(self.p.stdout.readline())
        if "error" in r:
            raise RuntimeError(r["error"])
        return r


class Python:
    """The python side: a device of oldmemo's backend"""

    def __init__(self):
        self.backend = oldmemo.Oldmemo(MemoryStorage())
        self.hx_device = None
        self.hx_bundle = None

    async def init(self):
        await self.backend.generate_pre_keys(100)

    async def bundle_xml(self):
        return etree.serialize_bundle(await self.backend.get_bundle(PY_JID, PY_DEVICE))

    def sign_bit(self):
        return bool((self.hx_bundle.identity_key[31] >> 7) & 1)

    async def encrypt(self, text):
        """A message for the haxe device: the fields of its <encrypted> element"""
        content, key = await (
            self.backend.encrypt_plaintext(text.encode())
            if text is not None
            else self.backend.encrypt_empty()
        )
        session = await self.backend.load_session(HX_JID, self.hx_device)
        if session is None:
            session, encrypted = await self.backend.build_session_active(
                HX_JID, self.hx_device, self.hx_bundle, key
            )
        else:
            encrypted = await self.backend.encrypt_key_material(session, key)
        await self.backend.store_session(session)
        exchange = None if session.confirmed else session.key_exchange
        xml = etree.serialize_message(
            Message(
                oldmemo.NAMESPACE,
                PY_JID,
                PY_DEVICE,
                content,
                frozenset({(encrypted, exchange)}),
            )
        )
        k = xml.find(f"{NS}header/{NS}key")
        payload = xml.find(f"{NS}payload")
        return dict(
            key=k.text,
            preKey=k.get("prekey") == "true",
            iv=xml.find(f"{NS}header/{NS}iv").text,
            payload=None if payload is None else payload.text,
        )

    async def decrypt(self, m):
        """A message of the haxe device, as its <encrypted> element would carry it"""
        data = unb64(m["key"])
        if m["preKey"]:
            exchange, authenticated = oldmemo.KeyExchangeImpl.parse(
                data, self.sign_bit()
            )
            encrypted = oldmemo.EncryptedKeyMaterialImpl.parse(
                authenticated, PY_JID, PY_DEVICE
            )
            session = await self.backend.load_session(HX_JID, self.hx_device)
            if session is not None and session.key_exchange.builds_same_session(
                exchange
            ):
                key = await self.backend.decrypt_key_material(session, encrypted)
            else:
                session, key = await self.backend.build_session_passive(
                    HX_JID, self.hx_device, exchange, encrypted
                )
        else:
            encrypted = oldmemo.EncryptedKeyMaterialImpl.parse(data, PY_JID, PY_DEVICE)
            session = await self.backend.load_session(HX_JID, self.hx_device)
            key = await self.backend.decrypt_key_material(session, encrypted)
        await self.backend.store_session(session)
        if m["payload"] is None:
            return None
        return (
            await self.backend.decrypt_plaintext(
                oldmemo.ContentImpl(unb64(m["payload"]), unb64(m["iv"])), key
            )
        ).decode()


def bundle_element(b):
    """The <bundle> of the haxe device"""
    e = ET.Element(f"{NS}bundle")
    ET.SubElement(
        e, f"{NS}signedPreKeyPublic", signedPreKeyId=str(b["signedPreKeyId"])
    ).text = b["signedPreKey"]
    ET.SubElement(e, f"{NS}signedPreKeySignature").text = b["signedPreKeySignature"]
    ET.SubElement(e, f"{NS}identityKey").text = b["identityKey"]
    keys = ET.SubElement(e, f"{NS}prekeys")
    for k in b["preKeys"]:
        ET.SubElement(keys, f"{NS}preKeyPublic", preKeyId=str(k["id"])).text = k["key"]
    return e


async def conversation(peer, py, first):
    """Messages both ways, some out of order, and empty ones"""
    to_hx = lambda text: py.encrypt(text)
    read_hx = lambda m: peer(cmd="decrypt", jid=PY_JID, device=PY_DEVICE, **m)["text"]
    to_py = lambda text: peer(cmd="encrypt", jid=PY_JID, device=PY_DEVICE, text=text)

    if first == "python":
        m = await to_hx("hello from python")
        check(m["preKey"], "python: first message is a key exchange")
        check(read_hx(m) == "hello from python", "haxe reads python's first message")
        m2 = await to_hx("second, before an answer")
        check(
            read_hx(m2) == "second, before an answer",
            "haxe reads python's second key exchange",
        )
        r = to_py("hello from haxe")
        check(not r["preKey"], "haxe answers without key exchange")
        check(await py.decrypt(r) == "hello from haxe", "python reads haxe's answer")
    else:
        m = to_py("hello from haxe")
        check(m["preKey"], "haxe: first message is a key exchange")
        check(
            await py.decrypt(m) == "hello from haxe",
            "python reads haxe's first message",
        )
        m2 = to_py("second, before an answer")
        check(
            await py.decrypt(m2) == "second, before an answer",
            "python reads haxe's second key exchange",
        )
        r = await to_hx("hello from python")
        check(read_hx(r) == "hello from python", "haxe reads python's answer")

    rnd = random.Random(1)
    for round in range(6):
        # a few messages each way, read out of order
        from_py = []
        for i in range(4):
            t = f"py {round}.{i} " + "x" * rnd.randrange(0, 60)
            from_py.append((t, await to_hx(t)))
        rnd.shuffle(from_py)
        check(
            all(read_hx(m) == t for t, m in from_py),
            f"haxe reads python's messages out of order ({round})",
        )
        from_hx = [
            (f"hx {round}.{i} ü→😀", to_py(f"hx {round}.{i} ü→😀")) for i in range(4)
        ]
        rnd.shuffle(from_hx)
        ok = True
        for t, m in from_hx:
            ok = ok and await py.decrypt(m) == t
        check(ok, f"python reads haxe's messages out of order ({round})")

    check(read_hx(await to_hx(None)) is None, "haxe reads an empty message")
    check(await py.decrypt(to_py(None)) is None, "python reads an empty message")
    long = "long " * 2000
    check(read_hx(await to_hx(long)) == long, "haxe reads a long message")
    check(await py.decrypt(to_py(long)) == long, "python reads a long message")


async def main(cmd):
    for first in ("python", "haxe"):
        for run in range(3):
            # new devices each time: the sign bit of the keys differs
            peer = Peer(cmd)
            py = Python()
            await py.init()
            hx = peer(cmd="bundle")
            py.hx_device = hx["device"]
            py.hx_bundle = etree.parse_bundle(bundle_element(hx), HX_JID, hx["device"])
            if first == "haxe":
                e = await py.bundle_xml()
                pre = e.findall(f"{NS}prekeys/{NS}preKeyPublic")[run]
                peer(
                    cmd="start",
                    jid=PY_JID,
                    device=PY_DEVICE,
                    identityKey=e.find(f"{NS}identityKey").text,
                    signedPreKeyId=int(
                        e.find(f"{NS}signedPreKeyPublic").get("signedPreKeyId")
                    ),
                    signedPreKey=e.find(f"{NS}signedPreKeyPublic").text,
                    signedPreKeySignature=e.find(f"{NS}signedPreKeySignature").text,
                    preKeyId=int(pre.get("preKeyId")),
                    preKey=pre.text,
                )
            print(f"-- {first} starts ({run + 1})")
            await conversation(peer, py, first)
            peer.p.stdin.close()
            peer.p.wait()
    print("all ok" if failures == 0 else f"{failures} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
