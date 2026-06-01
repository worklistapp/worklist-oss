import { decodeBase64, encodeBase64 } from './base64'
import { encodeHpkeEnvelope, hpkeSeal } from './hpke'

const textEncoder = new TextEncoder()
const AGENT_RECIPIENT_PUBLIC_KEY_BYTES = 32

export async function buildAgentGrantCiphertext(params: {
  recipientPublicKey: string
  workListId: string
  listKey: Uint8Array
}): Promise<string> {
  const recipientPublicKey = decodeBase64(params.recipientPublicKey)
  if (recipientPublicKey.length !== AGENT_RECIPIENT_PUBLIC_KEY_BYTES) {
    throw new Error(
      `Agent recipient public key must decode to ${AGENT_RECIPIENT_PUBLIC_KEY_BYTES} bytes.`,
    )
  }
  const context = textEncoder.encode(`worklist.agent.grant:${params.workListId}`)
  const seal = await hpkeSeal({
    recipientPublicKey,
    info: context,
    aad: context,
    plaintext: params.listKey,
  })
  return encodeBase64(encodeHpkeEnvelope(seal))
}
