const base64Tail = ["", "===", "==", "="]

export function buf(value: string | Buffer): Buffer {
  return typeof value === "string" ? Buffer.from(value) : value
}

export function prefixed(prefix: string | Buffer, payload: string | Buffer): Buffer {
  return Buffer.concat([buf(prefix), buf(payload)])
}

export function jsonEncode(data: any) {
  return Buffer.from(JSON.stringify(data))
}

export function jsonDecode(data?: Buffer) {
  return data && JSON.parse(data.toString())
}

export function base64urlEncode(data: Buffer): string {
  return data.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function base64urlDecode(encoded: string): Buffer {
  let base64 = encoded.replace(/-/g, "+").replace(/_/g, "/") + base64Tail[encoded.length % 4]
  return Buffer.from(base64, "base64")
}