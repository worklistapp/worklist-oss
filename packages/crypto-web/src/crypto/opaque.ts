import { client as opaqueClient, ready as opaqueReady } from '@serenity-kit/opaque'

const SERVER_IDENTIFIER = 'worklist.api'

function ensureEmailIdentifier(email: string) {
  return email.trim().toLowerCase()
}

async function waitForOpaqueReady() {
  await opaqueReady
}

export type OpaqueRegistrationStart = {
  clientRegistrationState: string
  registrationRequest: string
}

export type OpaqueRegistrationFinishInput = {
  password: string
  clientRegistrationState: string
  serverRegistrationState: string
  email: string
}

export type OpaqueLoginStart = {
  clientLoginState: string
  startLoginRequest: string
}

export type OpaqueLoginFinishInput = {
  password: string
  clientLoginState: string
  serverLoginResponse: string
  email: string
}

export async function startOpaqueRegistration(password: string): Promise<OpaqueRegistrationStart> {
  await waitForOpaqueReady()
  return opaqueClient.startRegistration({ password })
}

export async function finishOpaqueRegistration(input: OpaqueRegistrationFinishInput) {
  await waitForOpaqueReady()
  return opaqueClient.finishRegistration({
    password: input.password,
    clientRegistrationState: input.clientRegistrationState,
    registrationResponse: input.serverRegistrationState,
    identifiers: {
      client: ensureEmailIdentifier(input.email),
      server: SERVER_IDENTIFIER,
    },
  })
}

export async function startOpaqueLogin(password: string): Promise<OpaqueLoginStart> {
  await waitForOpaqueReady()
  return opaqueClient.startLogin({ password })
}

export async function finishOpaqueLogin(input: OpaqueLoginFinishInput) {
  await waitForOpaqueReady()
  return opaqueClient.finishLogin({
    password: input.password,
    clientLoginState: input.clientLoginState,
    loginResponse: input.serverLoginResponse,
    identifiers: {
      client: ensureEmailIdentifier(input.email),
      server: SERVER_IDENTIFIER,
    },
  })
}

export type OpaquePasswordChangeStart = {
  oldPasswordLoginRequest: string
  oldPasswordClientLoginState: string
  newPasswordRegistrationRequest: string
  newPasswordClientRegistrationState: string
}

export type OpaquePasswordChangeFinishInput = {
  oldPassword: string
  oldPasswordClientLoginState: string
  oldPasswordServerChallenge: string
  newPassword: string
  newPasswordClientRegistrationState: string
  newPasswordServerResponse: string
  email: string
}

export type OpaquePasswordChangeFinishResult = {
  oldPasswordFinishMessage: string
  newPasswordFinishMessage: string
  oldPasswordExportKey: string
  newPasswordExportKey: string
}

export async function startOpaquePasswordChange(
  oldPassword: string,
  newPassword: string,
): Promise<OpaquePasswordChangeStart> {
  await waitForOpaqueReady()

  const [oldPasswordLogin, newPasswordRegistration] = await Promise.all([
    startOpaqueLogin(oldPassword),
    startOpaqueRegistration(newPassword),
  ])

  return {
    oldPasswordLoginRequest: oldPasswordLogin.startLoginRequest,
    oldPasswordClientLoginState: oldPasswordLogin.clientLoginState,
    newPasswordRegistrationRequest: newPasswordRegistration.registrationRequest,
    newPasswordClientRegistrationState: newPasswordRegistration.clientRegistrationState,
  }
}

export async function finishOpaquePasswordChange(
  input: OpaquePasswordChangeFinishInput,
): Promise<OpaquePasswordChangeFinishResult> {
  await waitForOpaqueReady()

  // Finish old password verification
  const oldPasswordFinish = await finishOpaqueLogin({
    password: input.oldPassword,
    clientLoginState: input.oldPasswordClientLoginState,
    serverLoginResponse: input.oldPasswordServerChallenge,
    email: input.email,
  })

  if (!oldPasswordFinish?.finishLoginRequest) {
    throw new Error('Failed to verify old password')
  }

  // Finish new password registration
  const newPasswordFinish = await finishOpaqueRegistration({
    password: input.newPassword,
    clientRegistrationState: input.newPasswordClientRegistrationState,
    serverRegistrationState: input.newPasswordServerResponse,
    email: input.email,
  })

  if (!newPasswordFinish?.registrationRecord) {
    throw new Error('Failed to register new password')
  }

  return {
    oldPasswordFinishMessage: oldPasswordFinish.finishLoginRequest,
    newPasswordFinishMessage: newPasswordFinish.registrationRecord,
    oldPasswordExportKey: oldPasswordFinish.exportKey,
    newPasswordExportKey: newPasswordFinish.exportKey,
  }
}
