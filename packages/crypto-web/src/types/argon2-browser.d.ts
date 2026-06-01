declare module 'argon2-browser' {
  export enum ArgonType {
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
  }

  export interface HashOptions {
    pass: string | Uint8Array
    salt: string | Uint8Array
    time?: number
    mem?: number
    hashLen?: number
    parallelism?: number
    type?: ArgonType
    raw?: boolean
    secret?: Uint8Array
    ad?: Uint8Array
    wasmBinary?: ArrayBuffer | Uint8Array
  }

  export interface HashResult {
    hash: Uint8Array
    hashHex: string
    encoded: string
  }

  export function hash(options: HashOptions): Promise<HashResult>

  export interface Argon2Module {
    hash: typeof hash
    ArgonType: typeof ArgonType
  }

  const module: Argon2Module
  export default module
}
