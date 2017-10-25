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

  decodeBuffer(payload: Buffer): Buffer | void {
    try {
      const data = payload.slice(32)

      if (this.sign(data).equals(payload.slice(0, 32))) {
        return data
      }
    } catch (e) {
    }
  }

  encodeBase64<T = any>(payload: T): string {
    return this.encodeBuffer(encode(toJSON(payload))).toString("base64")
  }

  decodeBase64<T>(encoded: string): T | void {
    const buffer = this.decodeBuffer(Buffer.from(encoded, "base64"))

    if (buffer) {
      return decode(buffer)
    }
  }

  encodeBase64URL<T = any>(payload: T): string {
    return base64URLEncode(this.encodeBuffer(encode(toJSON(payload))))
  }

  decodeBase64URL<T>(encoded: string): T | void {
    const buffer = this.decodeBuffer(base64URLDecode(encoded))

    if (buffer) {
      return decode(buffer)
    }
  }
}