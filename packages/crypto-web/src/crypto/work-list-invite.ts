import { decode as cborDecode, encode as cborEncode } from 'cbor-x'

import { SEALED_PAYLOAD_VERSION } from './constants'
import { decodeBase64, encodeBase64 } from './base64'
import { deriveInviteKeyPair } from './invite-key'
import { computeKeyFingerprint, encodeHpkeEnvelope, hpkeOpen, hpkeSeal } from './hpke'
import { hkdfExpand } from './hkdf'
import { randomBytes } from './random'
import { parseSealedPayload, serializeSealedPayload } from './sealed-payload'
import { getStrongBoxBridge } from './strong-box'
import { sealWorkListKeyForOwner } from './work-list'
import type { SealedBlobPayload } from './types'

const encoder = new TextEncoder()
const INVITE_MEMBER_CONTEXT = encoder.encode('worklist.invite.member')
const INVITE_PACKAGE_CONTEXT = encoder.encode('worklist.invite.package')
const MEMBERSHIP_PROOF_LABEL = 'accept:'
const MEMBER_SALT_BYTES = 32
const INVITE_PACKAGE_SESSION_KEY_BYTES = 32

export type WorkListInviteRole = 'member' | 'admin'

export type WorkListInviteTarget = {
  userId: string
  email: string
  name: string
  membershipRole: WorkListInviteRole
}

export type WorkListInvitePayload<TInviteKeyProof = unknown> = {
  email: string
  role: WorkListInviteRole
  membershipId: string
  workListKeyCiphertext: string
  recipientCiphertext: string
  invitePackageCiphertext: string
  saltMember: string
  expiresAt: string
  payloadBindingKey: string
  inviteKeyProof: TInviteKeyProof
}

export type CreateWorkListInvitePayloadParams<TInviteKeyProof = unknown> = {
  workListId: string
  listKey: Uint8Array
  bindingKey: Uint8Array
  recipientPublicKey: Uint8Array
  target: WorkListInviteTarget
  listTitle: string
  membershipId: string
  inviter?: {
    id: string
    name: string
    email: string
  }
  expiresAt: Date | string
  inviteKeyProof: TInviteKeyProof
}

export type PendingWorkListInvitation = {
  workListId: string
  membershipId?: string | null
  recipientCiphertext?: string | null
  saltMember?: string | null
  role: string
  workListKeyCiphertext: string
}

type InviteMemberEnvelope = {
  kind: string
  version: number
  body?: {
    work_list_id?: string
    membership_id?: string
    key?: string
    salt_member?: string
    user_id?: string
  }
}

type RecipientEnvelope = {
  kind: string
  version: number
  body?: {
    work_list_id?: string
    membership_id?: string
    role?: string
    key?: string
  }
}

export async function createWorkListInvitePayload<TInviteKeyProof = unknown>(
  params: CreateWorkListInvitePayloadParams<TInviteKeyProof>,
): Promise<WorkListInvitePayload<TInviteKeyProof>> {
  if (!params.membershipId) {
    throw new Error('Membership id is required for HPKE invite binding')
  }

  const salt = randomBytes(MEMBER_SALT_BYTES)
  const memberEnvelopeKey = await deriveMemberEnvelopeKey({
    listKey: params.listKey,
    userId: params.target.userId,
    salt,
  })
  const issuedAt = new Date().toISOString()
  const expiresAt = typeof params.expiresAt === 'string' ? params.expiresAt : params.expiresAt.toISOString()
  const bridge = await getStrongBoxBridge()

  const workListKeyCiphertext = await sealInviteMemberEnvelope({
    bridge,
    key: memberEnvelopeKey,
    payload: {
      kind: 'work_list.invite.member',
      version: 1,
      body: {
        work_list_id: params.workListId,
        user_id: params.target.userId,
        email: params.target.email,
        key: encodeBase64(memberEnvelopeKey),
        salt_member: encodeBase64(salt),
        role: params.target.membershipRole,
        issued_at: issuedAt,
      },
    },
  })
  const recipientCiphertext = await createRecipientCiphertext({
    workListId: params.workListId,
    membershipBindingId: params.membershipId,
    role: params.target.membershipRole,
    listKey: params.listKey,
    recipientPublicKey: params.recipientPublicKey,
    issuedAt,
  })
  const invitePackageCiphertext = await sealInvitePackage({
    bridge,
    metadata: {
      kind: 'work_list.invite.package',
      version: 1,
      body: {
        work_list_id: params.workListId,
        title: params.listTitle,
        invitee: {
          user_id: params.target.userId,
          email: params.target.email,
          name: params.target.name || params.target.email,
          role: params.target.membershipRole,
        },
        inviter: params.inviter ?? null,
        issued_at: issuedAt,
        expires_at: expiresAt,
      },
    },
  })

  return {
    email: params.target.email,
    role: params.target.membershipRole,
    membershipId: params.membershipId,
    workListKeyCiphertext: workListKeyCiphertext.base64,
    recipientCiphertext: recipientCiphertext.base64,
    invitePackageCiphertext: invitePackageCiphertext.base64,
    saltMember: encodeBase64(salt),
    expiresAt,
    payloadBindingKey: encodeBase64(params.bindingKey),
    inviteKeyProof: params.inviteKeyProof,
  }
}

export async function buildWorkListInviteAcceptancePayload(params: {
  invitation: PendingWorkListInvitation
  dataKey: Uint8Array
  userId: string
}): Promise<{
  workListKeyCiphertext: string
  membershipProof: string
}> {
  const { invitation, dataKey, userId } = params
  if (!invitation.membershipId) {
    throw new Error('Invitation is missing the membership identifier required for HPKE binding.')
  }
  if (!invitation.recipientCiphertext) {
    throw new Error('Invitation is missing the HPKE recipient ciphertext required to recover the list key.')
  }
  if (!invitation.saltMember) {
    throw new Error('Invitation is missing the membership salt required to derive keys.')
  }

  const salt = decodeBase64(invitation.saltMember)
  const membershipRole = normalizeMembershipRole(invitation.role)
  const listKey = await decryptRecipientCiphertext({
    invitation,
    dataKey,
    userId,
    membershipBindingId: invitation.membershipId,
    role: membershipRole,
  })
  const memberEnvelopeKey = await deriveMemberEnvelopeKey({
    listKey,
    userId,
    salt,
  })
  await verifyInviteEnvelope({
    ciphertext: invitation.workListKeyCiphertext,
    memberEnvelopeKey,
    userId,
  })

  const membershipCiphertext = await sealWorkListKeyForOwner({
    listKey,
    dataKey,
  })
  const membershipProof = await computeMembershipProof(memberEnvelopeKey, invitation.membershipId)

  return {
    workListKeyCiphertext: membershipCiphertext.base64,
    membershipProof,
  }
}

export function encodeRecipientBindingContext(params: {
  workListId: string
  membershipBindingId: string
  role: WorkListInviteRole
  keyFingerprintB64: string
}): Uint8Array {
  const payload = {
    kind: 'work_list.invite.binding',
    version: 1,
    body: {
      work_list_id: params.workListId,
      membership_id: params.membershipBindingId,
      role: params.role,
      key_fingerprint: params.keyFingerprintB64,
    },
  }
  return toUint8Array(cborEncode(payload))
}

export async function deriveMemberEnvelopeKey(params: {
  listKey: Uint8Array
  userId: string
  salt: Uint8Array
}): Promise<Uint8Array> {
  if (!params.userId) {
    throw new Error('User id is required to derive membership keys')
  }
  return hkdfExpand({
    parent: params.listKey,
    info: `member:${params.userId}:${encodeBase64(params.salt)}`,
  })
}

export async function decryptRecipientCiphertext(params: {
  invitation: Pick<PendingWorkListInvitation, 'workListId' | 'recipientCiphertext'>
  dataKey: Uint8Array
  userId: string
  membershipBindingId: string
  role: WorkListInviteRole
}): Promise<Uint8Array> {
  const { invitation, dataKey, userId, membershipBindingId, role } = params
  if (!invitation.recipientCiphertext) {
    throw new Error('Invitation is missing the HPKE recipient ciphertext required to recover the list key.')
  }
  const { privateKey, publicKey } = await deriveInviteKeyPair({ dataKey, userId })
  try {
    const keyFingerprint = await computeKeyFingerprint(publicKey)
    const bindingContext = encodeRecipientBindingContext({
      workListId: invitation.workListId,
      membershipBindingId,
      role,
      keyFingerprintB64: encodeBase64(keyFingerprint),
    })
    const sealed = parseSealedPayload(invitation.recipientCiphertext)
    const plaintext = await hpkeOpen({
      recipientPrivateKey: privateKey,
      info: bindingContext,
      aad: bindingContext,
      envelope: sealed.ciphertext,
    })
    const envelope = cborDecode(plaintext) as RecipientEnvelope
    if (!envelope || envelope.kind !== 'work_list.invite.recipient' || typeof envelope.body !== 'object') {
      throw new Error('Recipient HPKE payload is malformed')
    }
    const { work_list_id, membership_id, role: envelopeRole, key } = envelope.body
    if (work_list_id && work_list_id !== invitation.workListId) {
      throw new Error('Recipient HPKE payload targets a different work list')
    }
    if (envelopeRole && envelopeRole !== role) {
      throw new Error('Recipient HPKE payload role mismatch')
    }
    if (membership_id && membership_id !== membershipBindingId) {
      throw new Error('Recipient HPKE payload does not belong to this membership assignment')
    }
    if (!key) {
      throw new Error('Recipient HPKE payload is missing the work list key')
    }
    const listKey = decodeBase64(key)
    if (listKey.length === 0) {
      throw new Error('Recipient HPKE payload contains an empty work list key')
    }
    return listKey
  } finally {
    zeroBytes(privateKey)
  }
}

export async function verifyInviteEnvelope(params: {
  ciphertext: string
  memberEnvelopeKey: Uint8Array
  userId: string
}): Promise<void> {
  const sealed = parseSealedPayload(params.ciphertext)
  const bridge = await getStrongBoxBridge()
  const plaintext = await bridge.decrypt({
    key: params.memberEnvelopeKey,
    context: INVITE_MEMBER_CONTEXT,
    ciphertext: sealed.ciphertext,
  })

  const envelope = cborDecode(plaintext) as InviteMemberEnvelope
  if (!envelope || envelope.kind !== 'work_list.invite.member' || typeof envelope.body !== 'object') {
    throw new Error('Invitation payload is malformed')
  }

  if (envelope.body.user_id && envelope.body.user_id !== params.userId) {
    throw new Error('Invitation does not belong to the current user')
  }

  const memberKeyB64 = envelope.body.key
  if (!memberKeyB64) {
    throw new Error('Invitation payload is missing the member key')
  }

  const memberKey = decodeBase64(memberKeyB64)
  if (memberKey.length === 0) {
    throw new Error('Invitation member key is empty')
  }

  if (!areUint8ArraysEqual(memberKey, params.memberEnvelopeKey)) {
    throw new Error('Invitation member key does not match the derived envelope key')
  }
}

export async function computeMembershipProof(memberKey: Uint8Array, membershipId: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto API is unavailable for membership proof generation')
  }
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(memberKey),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign'],
  )
  const mac = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    encoder.encode(`${MEMBERSHIP_PROOF_LABEL}${membershipId}`),
  )
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(mac))
  return encodeBase64(new Uint8Array(digest))
}

function normalizeMembershipRole(role: string): WorkListInviteRole {
  if (role === 'member' || role === 'admin') {
    return role
  }
  throw new Error(`Unsupported membership role: ${role}`)
}

async function createRecipientCiphertext(params: {
  workListId: string
  membershipBindingId: string
  role: WorkListInviteRole
  listKey: Uint8Array
  recipientPublicKey: Uint8Array
  issuedAt: string
}): Promise<SealedBlobPayload> {
  const keyFingerprint = await computeKeyFingerprint(params.recipientPublicKey)
  const bindingContext = encodeRecipientBindingContext({
    workListId: params.workListId,
    membershipBindingId: params.membershipBindingId,
    role: params.role,
    keyFingerprintB64: encodeBase64(keyFingerprint),
  })
  const plaintext = encodeRecipientPlaintext({
    workListId: params.workListId,
    membershipBindingId: params.membershipBindingId,
    role: params.role,
    listKey: params.listKey,
    issuedAt: params.issuedAt,
  })
  const hpkeResult = await hpkeSeal({
    recipientPublicKey: params.recipientPublicKey,
    info: bindingContext,
    aad: bindingContext,
    plaintext,
  })
  return toSealedBlobPayload(encodeHpkeEnvelope(hpkeResult))
}

function encodeRecipientPlaintext(params: {
  workListId: string
  membershipBindingId: string
  role: WorkListInviteRole
  listKey: Uint8Array
  issuedAt: string
}): Uint8Array {
  const payload = {
    kind: 'work_list.invite.recipient',
    version: 1,
    body: {
      work_list_id: params.workListId,
      membership_id: params.membershipBindingId,
      role: params.role,
      key: encodeBase64(params.listKey),
      issued_at: params.issuedAt,
    },
  }
  return toUint8Array(cborEncode(payload))
}

async function sealInviteMemberEnvelope(params: {
  bridge: Awaited<ReturnType<typeof getStrongBoxBridge>>
  key: Uint8Array
  payload: Record<string, unknown>
}): Promise<SealedBlobPayload> {
  const plaintext = toUint8Array(cborEncode(params.payload))
  const ciphertext = await params.bridge.encrypt({
    key: params.key,
    context: INVITE_MEMBER_CONTEXT,
    plaintext,
  })
  return toSealedBlobPayload(ciphertext)
}

async function sealInvitePackage(params: {
  bridge: Awaited<ReturnType<typeof getStrongBoxBridge>>
  metadata: Record<string, unknown>
}): Promise<SealedBlobPayload> {
  const sessionKey = randomBytes(INVITE_PACKAGE_SESSION_KEY_BYTES)
  const plaintext = toUint8Array(cborEncode(params.metadata))
  const ciphertext = await params.bridge.encrypt({
    key: sessionKey,
    context: INVITE_PACKAGE_CONTEXT,
    plaintext,
  })
  return toSealedBlobPayload(ciphertext)
}

function toSealedBlobPayload(ciphertext: Uint8Array): SealedBlobPayload {
  const bytes = serializeSealedPayload({
    version: SEALED_PAYLOAD_VERSION,
    ciphertext,
  })
  return {
    bytes,
    base64: encodeBase64(bytes),
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const { buffer, byteOffset, byteLength } = bytes
  if (buffer instanceof ArrayBuffer) {
    return buffer.slice(byteOffset, byteOffset + byteLength)
  }
  const copy = new Uint8Array(byteLength)
  copy.set(bytes)
  return copy.buffer
}

function toUint8Array(value: Uint8Array | ArrayBuffer | ArrayBufferLike): Uint8Array {
  const source = value instanceof Uint8Array ? value : new Uint8Array(value as ArrayBufferLike)
  const copy = new Uint8Array(source.length)
  copy.set(source)
  return copy
}

function zeroBytes(bytes?: Uint8Array | null) {
  if (!bytes) {
    return
  }
  bytes.fill(0)
}

function areUint8ArraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false
  }
  let difference = 0
  for (let idx = 0; idx < left.length; idx += 1) {
    difference |= left[idx] ^ right[idx]
  }
  return difference === 0
}
