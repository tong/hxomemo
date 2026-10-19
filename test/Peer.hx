import haxe.Json;
import haxe.crypto.Base64;
import haxe.io.Bytes;
import omemo.Account;

/**
	A device for the tests with other implementations (`interop.py`): commands as JSON lines on stdin, answers on
	stdout; keys encoded as in the XML (type 5 and key), base64.
**/
class Peer {
	static function main() {
		final account = Account.create();
		final stdin = Sys.stdin(), stdout = Sys.stdout();
		inline function b(v:String):Bytes
			return Base64.decode(v);
		inline function s(v:Bytes):String
			return Base64.encode(v);
		while (true) {
			final line = try stdin.readLine() catch (e:haxe.io.Eof) break;
			final c:Dynamic = Json.parse(line);
			final reply:Dynamic = try switch (c.cmd : String) {
				case "bundle":
					final bundle = account.bundle();
					{
						device: account.deviceId,
						identityKey: s(omemo.KeyPair.encode(bundle.identityKey)),
						signedPreKeyId: bundle.signedPreKeyId,
						signedPreKey: s(omemo.KeyPair.encode(bundle.signedPreKey)),
						signedPreKeySignature: s(bundle.signedPreKeySignature),
						preKeys: [
							for (k in bundle.preKeys) {
								id: k.id,
								key: s(omemo.KeyPair.encode(k.key))
							}
						],
					};
				case "start":
					account.startSession(c.jid, c.device, {
						identityKey: omemo.KeyPair.decode(b(c.identityKey)),
						signedPreKeyId: c.signedPreKeyId,
						signedPreKey: omemo.KeyPair.decode(b(c.signedPreKey)),
						signedPreKeySignature: b(c.signedPreKeySignature),
						preKeyId: c.preKeyId,
						preKey: omemo.KeyPair.decode(b(c.preKey)),
					});
					{};
				case "encrypt":
					final e = account.encrypt(c.text == null ? null : Bytes.ofString(c.text), [{jid: c.jid, device: c.device}]);
					{
						iv: s(e.iv),
						payload: e.payload == null ? null : s(e.payload),
						key: s(e.keys[0].data),
						preKey: e.keys[0].preKey
					};
				case "decrypt":
					final d = account.decrypt(c.jid, c.device, b(c.key), c.preKey, b(c.iv), c.payload == null ? null : b(c.payload));
					{text: d.plaintext?.toString(), newSession: d.newSession, preKeyUsed: d.preKeyUsed};
				case "fingerprint":
					{fingerprint: account.fingerprint()};
				case other:
					{error: 'unknown command $other'};
			} catch (e) {
				{error: Std.string(e)};
			}
			stdout.writeString(Json.stringify(reply) + "\n");
			stdout.flush();
		}
	}
}
