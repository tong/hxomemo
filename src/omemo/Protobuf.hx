package omemo;

import haxe.io.Bytes;
import haxe.io.BytesBuffer;

/**
	The protobuf encoding, as far as the messages of libsignal need it: varints (`uint32`) and byte fields.
**/
class Protobuf {
	/** Fields of a message by number: an `Int` (varint) or `Bytes` (length-delimited); unknown kinds are skipped **/
	public static function parse(b:Bytes, pos = 0, ?len:Int):Map<Int, Field> {
		final end = len == null ? b.length : pos + len;
		final fields = new Map<Int, Field>();
		inline function varint():Int {
			var v = 0, shift = 0;
			while (true) {
				if (pos >= end)
					throw new ProtobufError("truncated varint");
				final c = b.get(pos++);
				// uint32: the low 32 bits (the rest of a longer varint is dropped)
				if (shift < 32)
					v |= (c & 0x7f) << shift;
				shift += 7;
				if (c & 0x80 == 0)
					break;
				if (shift > 63)
					throw new ProtobufError("invalid varint");
			}
			return v;
		}
		while (pos < end) {
			final key = varint();
			final number = key >>> 3;
			switch key & 7 {
				case 0:
					fields.set(number, VInt(varint()));
				case 2:
					final n = varint();
					if (n < 0 || n > end - pos)
						throw new ProtobufError("truncated field");
					fields.set(number, VBytes(b.sub(pos, n)));
					pos += n;
				case 1:
					pos += 8;
				case 5:
					pos += 4;
				case t:
					throw new ProtobufError('unsupported wire type $t');
			}
		}
		if (pos > end)
			throw new ProtobufError("truncated field");
		return fields;
	}

	public static function int(fields:Map<Int, Field>, number:Int):Null<Int>
		return switch fields.get(number) {
			case VInt(v): v;
			case _: null;
		}

	public static function bytes(fields:Map<Int, Field>, number:Int):Null<Bytes>
		return switch fields.get(number) {
			case VBytes(v): v;
			case _: null;
		}
}

enum Field {
	VInt(v:Int);
	VBytes(v:Bytes);
}

/** Writes the fields of a message, in the order given **/
class ProtobufWriter {
	final buf = new BytesBuffer();

	public function new() {}

	function varint(v:Int) {
		// as unsigned 32 bit
		while (v >>> 7 != 0) {
			buf.addByte((v & 0x7f) | 0x80);
			v >>>= 7;
		}
		buf.addByte(v);
	}

	public function int(number:Int, v:Int):ProtobufWriter {
		varint(number << 3);
		varint(v);
		return this;
	}

	public function bytes(number:Int, v:Bytes):ProtobufWriter {
		varint((number << 3) | 2);
		varint(v.length);
		buf.add(v);
		return this;
	}

	public function getBytes():Bytes
		return buf.getBytes();
}

class ProtobufError extends haxe.Exception {}
