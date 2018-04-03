import { createHmac } from "crypto"
import { encode, decode } from "msgpack-lite"
import { toJSON } from "@iamdimka/helper"

const base64Tail = ["", "===", "==", "="]

function base64URLEncode(data: Buffer): string {
  return data.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function base64URLDecode(encoded: string): Buffer {
  let base64 = encoded.replace(/-/g, "+").replace(/_/g, "/") + base64Tail[encoded.length % 4]
  return Buffer.from(base64, "base64")
}

export class Token {
  protected _key: string | Buffer

  constructor(key?: string | Buffer) {
    this._key = key || ""
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

  decodeBuffer(payload: Buffer): Buffer | void {
    try {
      const data = payload.slice(32)

      if (this.sign(data).equals(payload.slice(0, 32))) {
        return data
      }
    } catch (e) {
    }
  }

  decodeBufferXOR(payload: Buffer, overhead: number = 1): Buffer | void {
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

  encodeBase64<T = any>(payload: T): string {
    return this.encodeBuffer(encode(toJSON(payload))).toString("base64")
  }

  encodeBase64XOR<T = any>(payload: T, overhead: number = 1): string {
    return this.encodeBufferXOR(encode(toJSON(payload)), overhead).toString("base64")
  }

  decodeBase64<T>(encoded: string): T | void {
    const buffer = this.decodeBuffer(Buffer.from(encoded, "base64"))

    if (buffer) {
      return decode(buffer)
    }
  }

  decodeBase64XOR<T = any>(encoded: string, overhead: number = 1): T | void {
    let buffer = this.decodeBufferXOR(Buffer.from(encoded, "base64"), overhead)

    if (buffer) {
      return decode(buffer)
    }
  }

  encodeBase64URL<T = any>(payload: T): string {
    return base64URLEncode(this.encodeBuffer(encode(toJSON(payload))))
  }

  encodeBase64URLXOR<T = any>(payload: T, overhead: number = 1): string {
    return base64URLEncode(this.encodeBufferXOR(encode(toJSON(payload)), overhead))
  }

  decodeBase64URL<T>(encoded: string): T | void {
    const buffer = this.decodeBuffer(base64URLDecode(encoded))

    if (buffer) {
      return decode(buffer)
    }
  }

  decodeBase64URLXOR<T>(encoded: string, overhead: number = 1): T | void {
    const buffer = this.decodeBufferXOR(base64URLDecode(encoded), overhead)

    if (buffer) {
      return decode(buffer)
    }
  }
}