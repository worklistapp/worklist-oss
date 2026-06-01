import { hkdfExpand } from './hkdf'
import { clampScalar, derivePublicKey } from './x25519'

const INVITE_KEY_INFO_PREFIX = 'invite:keypair'

export type InviteKeyPair = {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export async function deriveInviteKeyPair(params: {
  dataKey: Uint8Array
  userId?: string
}): Promise<InviteKeyPair> {
  if (!params.dataKey || params.dataKey.length === 0) {
    throw new Error('Data key is required to derive invite key material.')
  }

  const infoLabel = params.userId
    ? `${INVITE_KEY_INFO_PREFIX}:${params.userId}`
    : INVITE_KEY_INFO_PREFIX
  const seed = await hkdfExpand({
    parent: params.dataKey,
    info: infoLabel,
  })
  const privateKey = clampScalar(seed)
  const publicKey = await derivePublicKey(privateKey)
  return {
    privateKey,
    publicKey,
  }
}
