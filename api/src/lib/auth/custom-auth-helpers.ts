import type { APIGatewayProxyEvent } from 'aws-lambda'
import CryptoJS from 'crypto-js'
import { v4 as uuidv4 } from 'uuid'

import { CorsConfig, CorsContext, CorsHeaders, createCorsContext } from './cors'
import * as AuthError from './errors'
import { decryptSession, extractCookie, getSession } from './shared'
import { normalizeRequest } from './transforms'

/**
 * To use in src/lib/auth#getCurrentUser
 *
 * Use this type to tell the getCurrentUser function what the type of session is
 * @example
 * import {User} from '@prisma/client'
 *
 * //  key being used in dbAccessor in src/functions/auth.ts 👇
 * const getCurrentUser = async (session: DbAuthSession<User['id']>)
 */
interface AuthSession<TIdType = any> {
  id: TIdType
}

type AuthMethodNames =
  | 'forgotPassword'
  | 'getToken'
  | 'login'
  | 'logout'
  | 'resetPassword'
  | 'signup'
  | 'validateResetToken'
  | 'webAuthnRegOptions'
  | 'webAuthnRegister'
  | 'webAuthnAuthOptions'
  | 'webAuthnAuthenticate'

export type TAuthHandlerOptions<TUser = unknown> = {
  cookie?: {
    Path?: string
    HttpOnly?: boolean
    Secure?: boolean
    SameSite?: string
    Domain?: string
  }
  cors?: CorsConfig
  login: LoginFlowOptions<TUser>
  authFields: {
    id: string
  }
}

interface LoginFlowOptions<TUser = Record<string | number, any>> {
  /**
   * Allow users to login. Defaults to true.
   * Needs to be explicitly set to false to disable the flow
   */
  enabled?: boolean
  /**
   * Anything you want to happen before logging the user in. This can include
   * throwing an error to prevent login. If you do want to allow login, this
   * function must return an object representing the user you want to be logged
   * in, containing at least an `id` field (whatever named field was provided
   * for `authFields.id`). For example: `return { id: user.id }`
   */
  handler: (user: TUser) => any
  /**
   * Object containing error strings
   */
  errors?: {
    usernameOrPasswordMissing?: string
    usernameNotFound?: string
    incorrectPassword?: string
    flowNotEnabled?: string
  }
  /**
   * How long a user will remain logged in, in seconds
   */
  expires: number
}

type SetCookieHeader = { 'set-cookie': string }
type CsrfTokenHeader = { 'csrf-token': string }

const PAST_EXPIRES_DATE = new Date(
  '1970-01-01T00:00:00.000+00:00'
).toUTCString()

const buildResponseWithCorsHeaders = (
  response: {
    body?: string
    statusCode: number
    headers?: Record<string, string>
  },
  corsHeaders: CorsHeaders
) => {
  return {
    ...response,
    headers: {
      ...(response.headers || {}),
      ...corsHeaders,
    },
  }
}

type TResult<T, E> = { ok: true; data: T } | { ok: false; error: E }

const decrypt = (
  cookie
): TResult<
  { session: Record<string, any>; csrfToken: string },
  { info: { hasInvalidSession: boolean }; error: any }
> => {
  try {
    const [session, csrfToken] = decryptSession(getSession(cookie))
    return { ok: true, data: { session, csrfToken } }
  } catch (e) {
    return { ok: false, error: e }
  }
}

const notFoundResponse = () => {
  return {
    statusCode: 404,
  }
}

const okResponse = (
  body: string,
  headers = {},
  options = { statusCode: 200 }
) => {
  return {
    statusCode: options.statusCode,
    body: typeof body === 'string' ? body : JSON.stringify(body),
    headers: { 'Content-Type': 'application/json', ...headers },
  }
}

const badRequestResponse = (message: string) => {
  return {
    statusCode: 400,
    body: JSON.stringify({ error: message }),
    headers: { 'Content-Type': 'application/json' },
  }
}

// returns all the cookie attributes in an array with the proper expiration date
//
// pass the argument `expires` set to "now" to get the attributes needed to expire
// the session, or "future" (or left out completely) to set to `futureExpiresDate`
const cookieAttributes = ({
  prevCookie,
  expires = 'now',
  options = {},
}: {
  prevCookie: Record<string, any>
  expires?: 'now' | string
  options?: TAuthHandlerOptions['cookie']
}) => {
  const cookieOptions = { ...prevCookie, ...options } || {
    ...options,
  }
  const meta = Object.keys(cookieOptions)
    .map((key) => {
      const optionValue =
        cookieOptions[key as keyof TAuthHandlerOptions['cookie']]

      // Convert the options to valid cookie string
      if (optionValue === true) {
        return key
      } else if (optionValue === false) {
        return null
      } else {
        return `${key}=${optionValue}`
      }
    })
    .filter((v) => v)

  const expiresAt = expires === 'now' ? PAST_EXPIRES_DATE : expires
  meta.push(`Expires=${expiresAt}`)

  return meta
}

// encrypts a string with the SESSION_SECRET
const encrypt = (data: string) => {
  return CryptoJS.AES.encrypt(data, process.env.SESSION_SECRET as string)
}

// get _deleteSessionHeader() {
const deleteSessionHeader = (prevCookie) => {
  return {
    'set-cookie': [
      'session=',
      ...cookieAttributes({ prevCookie, expires: 'now' }),
    ].join(';'),
  }
}
// returns the set-cookie header to be returned in the request (effectively
// creates the session)
const createSessionHeader = (
  data: AuthSession,
  csrfToken: string,
  sessionExpiresDate,
  prevCookie
): SetCookieHeader => {
  const session = JSON.stringify(data) + ';' + csrfToken
  const encrypted = encrypt(session)
  const cookie = [
    `session=${encrypted.toString()}`,
    ...cookieAttributes({ prevCookie, expires: sessionExpiresDate }),
  ].join(';')

  return { 'set-cookie': cookie }
}

// TODO we may need to generate a new one every instance right?
const CSRF_TOKEN = uuidv4()

const loginResponse = (
  user: Record<string, any>,
  authFields: TAuthHandlerOptions['authFields'],
  sessionExpiresDate,
  prevCookie,
  statusCode = 200
): [
  { id: string },
  SetCookieHeader & CsrfTokenHeader,
  { statusCode: number }
] => {
  const sessionData = { id: user[authFields.id] }

  // TODO: this needs to go into graphql somewhere so that each request makes
  // a new CSRF token and sets it in both the encrypted session and the
  // csrf-token header
  const csrfToken = CSRF_TOKEN

  return [
    sessionData,
    {
      'csrf-token': csrfToken,
      ...createSessionHeader(
        sessionData,
        csrfToken,
        sessionExpiresDate,
        prevCookie
      ),
    },
    { statusCode },
  ]
}

const logoutResponse = (
  prevCookie,
  response?: Record<string, unknown>
): [string, SetCookieHeader] => {
  return [
    response ? JSON.stringify(response) : '',
    {
      ...deleteSessionHeader(prevCookie),
    },
  ]
}

const VERBS = {
  forgotPassword: 'POST',
  getToken: 'GET',
  login: 'POST',
  logout: 'POST',
  resetPassword: 'POST',
  signup: 'POST',
  validateResetToken: 'POST',
  webAuthnRegOptions: 'GET',
  webAuthnRegister: 'POST',
  webAuthnAuthOptions: 'GET',
  webAuthnAuthenticate: 'POST',
} as const

const SUPPORTED_METHODS = [
  'forgotPassword',
  'getToken',
  'login',
  'logout',
  'resetPassword',
  'signup',
  'validateResetToken',
  'webAuthnRegOptions',
  'webAuthnRegister',
  'webAuthnAuthOptions',
  'webAuthnAuthenticate',
]

// parses the event body into JSON, whether it's base64 encoded or not
const parseBody = (event: APIGatewayProxyEvent) => {
  if (event.body) {
    if (event.isBase64Encoded) {
      return JSON.parse(
        Buffer.from(event.body || '', 'base64').toString('utf-8')
      )
    } else {
      return JSON.parse(event.body)
    }
  } else {
    return {}
  }
}

const getAuthMethod = (event: APIGatewayProxyEvent, params) => {
  // try getting it from the query string, /.redwood/functions/auth?method=[methodName]
  let methodName = event.queryStringParameters?.method as AuthMethodNames

  if (!SUPPORTED_METHODS.includes(methodName) && params) {
    // try getting it from the body in JSON: { method: [methodName] }
    try {
      methodName = params.method
    } catch (e) {
      // there's no body, or it's not JSON, `handler` will return a 404
    }
  }

  return methodName
}

export async function invoke(
  event: APIGatewayProxyEvent,
  _context,
  options: TAuthHandlerOptions
) {
  const request = normalizeRequest(event)
  let corsHeaders = {}
  let corsContext: CorsContext | undefined

  if (options.cors) {
    corsContext = createCorsContext(options.cors)
  }

  if (corsContext) {
    corsHeaders = corsContext.getRequestHeaders(request)
    // Return CORS headers for OPTIONS requests
    if (corsContext.shouldHandleCors(request)) {
      return buildResponseWithCorsHeaders(
        { body: '', statusCode: 200 },
        corsHeaders
      )
    }
  }

  const cookie = extractCookie(event)
  const decryptResult = decrypt(cookie)

  const prevCookie = {}
  // if there was a problem decryption the session, just return the logout
  // response immediately
  if (
    decryptResult.ok === false &&
    decryptResult.error instanceof AuthError.SessionDecryptionError
  ) {
    return buildResponseWithCorsHeaders(
      okResponse(...logoutResponse(prevCookie)),
      corsHeaders
    )
  }

  const params = parseBody(event)
  // TODO
  const fns = {
    getToken: () => {
      // return logoutResponse(prevCookie)
      return ['id12312312']
    },
    login: async () => {
      console.log('loggin ingggnlasdfjk')
      const sessionExpiresAt = new Date()
      sessionExpiresAt.setSeconds(
        sessionExpiresAt.getSeconds() + options.login.expires
      )
      const sessionExpiresDate = sessionExpiresAt.toUTCString()

      const { enabled = true } = options.login
      if (!enabled) {
        throw new AuthError.FlowNotEnabledError(
          options.login?.errors?.flowNotEnabled || `Login flow is not enabled`
        )
      }
      // const { username, password } = this.params
      // const dbUser = await this._verifyUser(username, password)

      const handlerUser = await options.login.handler({ id: 'someid' })

      if (handlerUser == null || handlerUser[options.authFields.id] == null) {
        throw new AuthError.NoUserIdError()
      }

      return loginResponse(
        handlerUser,
        options.authFields,
        sessionExpiresDate,
        prevCookie
      )
    },
  }
  try {
    const method = getAuthMethod(event, params)

    // get the auth method the incoming request is trying to call
    if (!SUPPORTED_METHODS.includes(method)) {
      return buildResponseWithCorsHeaders(notFoundResponse(), corsHeaders)
    }

    // make sure it's using the correct verb, GET vs POST
    if (event.httpMethod !== VERBS[method]) {
      return buildResponseWithCorsHeaders(notFoundResponse(), corsHeaders)
    }

    // call whatever auth method was requested and return the body and headers
    const [body, headers, options = { statusCode: 200 }] = await fns[method]()

    return buildResponseWithCorsHeaders(
      okResponse(body, headers, options),
      corsHeaders
    )
  } catch (e: any) {
    if (e instanceof AuthError.WrongVerbError) {
      return buildResponseWithCorsHeaders(notFoundResponse(), corsHeaders)
    } else {
      return buildResponseWithCorsHeaders(
        badRequestResponse(e.message || e),
        corsHeaders
      )
    }
  }
}
