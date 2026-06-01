export type SealedBlobPayload = {
  bytes: Uint8Array
  base64: string
}

export type ValidatedSealedBlobPayload = SealedBlobPayload & {
  schemaHash: Uint8Array
}
