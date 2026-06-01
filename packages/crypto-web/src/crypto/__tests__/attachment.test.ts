import { encode as cborEncode } from 'cbor-x'
import { describe, expect, it, vi } from 'vitest'

import { decodeAttachmentBlobKey } from '../attachment'
import { SEALED_PAYLOAD_VERSION } from '../constants'
import { serializeSealedPayload } from '../sealed-payload'
import type { StrongBoxBridge } from '../strong-box'

describe('attachment crypto helpers', () => {
  it('decodes sealed blob keys into blob refs', async () => {
    const blobRef = {
      version: 1,
      object_key: 'workspaces/workspace-1/attachments/attachment-1',
      ciphertext_bytes: 123,
      file_key: new Uint8Array([1, 2, 3]),
      enc_context: 'worklist.attachment.blob.v1',
    }
    const plaintext = new Uint8Array(cborEncode(blobRef))
    const bridge: StrongBoxBridge = {
      encrypt: vi.fn(),
      decrypt: vi.fn(async () => plaintext),
    }
    const blobKey = serializeSealedPayload({
      version: SEALED_PAYLOAD_VERSION,
      ciphertext: new Uint8Array([9]),
    })

    const result = await decodeAttachmentBlobKey({
      listKey: new Uint8Array([0]),
      blobKey,
      strongBox: bridge,
    })

    expect(result).toEqual({
      version: 1,
      object_key: blobRef.object_key,
      ciphertext_bytes: blobRef.ciphertext_bytes,
      file_key: blobRef.file_key,
      enc_context: blobRef.enc_context,
    })
    expect(bridge.decrypt).toHaveBeenCalled()
  })
})
