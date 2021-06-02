import { createHmac } from "crypto"
import { base64urlDecode, base64urlEncode, buf, jsonDecode, jsonEncode, prefixed } from "./util"

export default class Token {
  protected _key: string | Buffer

  protected encode: (data: any) => Buffer = jsonEncode;
  protected decode: (buffer?: Buffer) => any = jsonDecode;

  constructor(key?: string | Buffer) {
    this._key = key || ""
  }

  useEncoder(encode: (data: any) => Buffer, decode: (buffer?: Buffer) => any) {
    this.encode = encode
    this.decode = decode
    return this
  }

  sign(payload: Buffer): Buffer {
    return createHmac("sha256", this._key).update(payload).digest()
  }

  encodeBuffer(payload: Buffer): Buffer {
    return Buffer.concat([
      this.sign(payload),
      payload
    ])
  }

  encodePrefixedBuffer(prefix: string | Buffer, payload: Buffer): Buffer {
    return this.encodeBuffer(prefixed(prefix, payload))
  }

  encodeBufferXOR(payload: Buffer, overhead: number = 1): Buffer {
    const signature = this.sign(payload)

    const result = Buffer.allocUnsafe(overhead + signature.length + payload.length)

    for (let i = 0; i < overhead; i++) {
      result[i] = Math.floor(Math.random() * 256)
    }

    let offset = 0

    for (let i = 0; i < signature.length; i++) {
      result[overhead + offset] = signature[i] ^ result[offset % overhead]
      offset++
    }

    for (let i = 0; i < payload.length; i++) {
      result[overhead + offset] = payload[i] ^ result[offset % overhead]
      offset++
    }

    return result
  }

  encodePrefixedBufferXOR(prefix: string | Buffer, payload: Buffer, overhead = 1): Buffer {
    return this.encodeBufferXOR(prefixed(prefix, payload), overhead)
  }

  decodeBuffer(payload: Buffer): Buffer | undefined {
    try {
      const data = payload.slice(32)

      if (this.sign(data).equals(payload.slice(0, 32))) {
        return data
      }
    } catch (e) {
    }
  }

  decodePrefixedBuffer(prefix: string | Buffer, payload: Buffer): Buffer | undefined {
    prefix = buf(prefix)

    if (!payload.slice(32, 32 + prefix.length).equals(prefix)) {
      return
    }

    return this.decodeBuffer(payload)?.slice(prefix.length)
  }

  decodeBufferXOR(payload: Buffer, overhead: number = 1): Buffer | undefined {
    const length = payload.length - overhead
    if (length < 0) {
      return
    }

    const res = Buffer.allocUnsafe(length)
    for (let i = 0; i < length; i++) {
      res[i] = payload[overhead + i] ^ payload[i % overhead]
    }

    return this.decodeBuffer(res)
  }

  decodePrefixedBufferXOR(prefix: string | Buffer, payload: Buffer, overhead: number = 1): Buffer | undefined {
    prefix = buf(prefix)
    const data = this.decodeBufferXOR(payload, overhead)
    if (data && data.slice(0, prefix.length).equals(prefix)) {
      return data.slice(prefix.length)
    }
  }

  encodeBase64<T = any>(payload: T): string {
    return this.encodeBuffer(this.encode(payload)).toString("base64")
  }

  encodePrefixedBase64<T = any>(prefix: string, payload: T): string {
    return this.encodePrefixedBuffer(prefix, this.encode(payload)).toString("base64")
  }

  encodeBase64XOR<T = any>(payload: T, overhead: number = 1): string {
    return this.encodeBufferXOR(this.encode(payload), overhead).toString("base64")
  }

  encodePrefixedBase64XOR<T = any>(prefix: string, payload: T, overhead: number = 1): string {
    return this.encodePrefixedBufferXOR(prefix, this.encode(payload), overhead).toString("base64")
  }

  decodePrefixedBase64<T>(prefix: string, encoded: string): T | undefined {
    return this.decode(this.decodePrefixedBuffer(prefix, Buffer.from(encoded, "base64")))
  }

  decodeBase64XOR<T = any>(encoded: string, overhead: number = 1): T | undefined {
    return this.decode(this.decodeBufferXOR(Buffer.from(encoded, "base64"), overhead))
  }

  decodePrefixedBase64XOR<T = any>(prefix: string, encoded: string, overhead: number = 1): T | undefined {
    return this.decode(this.decodePrefixedBufferXOR(prefix, Buffer.from(encoded, "base64"), overhead))
  }

  encodeBase64URL<T = any>(payload: T): string {
    return base64urlEncode(this.encodeBuffer(this.encode(payload)))
  }

  encodePrefixedBase64URL<T = any>(prefix: string, payload: T): string {
    return base64urlEncode(this.encodePrefixedBuffer(prefix, this.encode(payload)))
  }

  encodeBase64URLXOR<T = any>(payload: T, overhead: number = 1): string {
    return base64urlEncode(this.encodeBufferXOR(this.encode(payload), overhead))
  }

  encodePrefixedBase64URLXOR<T = any>(prefix: string, payload: T, overhead: number = 1): string {
    return base64urlEncode(this.encodePrefixedBufferXOR(prefix, this.encode(payload), overhead))
  }

  decodeBase64URL<T>(encoded: string): T | undefined {
    return this.decode(this.decodeBuffer(base64urlDecode(encoded)))
  }

  decodePrefixedBase64URL<T>(prefix: string, encoded: string): T | undefined {
    return this.decode(this.decodePrefixedBuffer(prefix, base64urlDecode(encoded)))
  }

  decodeBase64URLXOR<T>(encoded: string, overhead: number = 1): T | undefined {
    return this.decode(this.decodeBufferXOR(base64urlDecode(encoded), overhead))
  }

  decodePrefixedBase64URLXOR<T>(prefix: string, encoded: string, overhead: number = 1): T | undefined {
    return this.decode(this.decodePrefixedBufferXOR(prefix, base64urlDecode(encoded), overhead))
  }
}