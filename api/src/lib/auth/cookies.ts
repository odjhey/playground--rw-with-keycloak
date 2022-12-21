import { decryptSession, getSession } from './shared'

export type TCookie = Record<string, string>

export type TCookieOptions = {
  Path?: string
  HttpOnly?: boolean
  Secure?: boolean
  SameSite?: string
  Domain?: string
}

const PAST_EXPIRES_DATE = new Date(
  '1970-01-01T00:00:00.000+00:00'
).toUTCString()

// returns all the cookie attributes in an array with the proper expiration date
//
// pass the argument `expires` set to "now" to get the attributes needed to expire
// the session, or "future" (or left out completely) to set to `futureExpiresDate`
export const toAttributes = ({
  cookie,
  expires = 'now',
  options = {},
}: {
  cookie: TCookie
  expires?: 'now' | string
  options?: TCookieOptions
}) => {
  const cookieOptions = { ...cookie, ...options } || {
    ...options,
  }
  const meta = Object.keys(cookieOptions)
    .map((key) => {
      const optionValue = cookieOptions[key as keyof TCookieOptions]

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

export const decrypt = (
  rawCookie: string
): TResult<{ session: Record<string, string>; csrfToken: string }, Error> => {
  try {
    const rawSession = getSession(rawCookie)
    const [sessionObj, csrfToken] = decryptSession(rawSession)
    console.log('--x-x------x-x-- decrypt', { session: sessionObj, csrfToken })

    if (typeof sessionObj === 'object') {
      return { ok: true, data: { session: sessionObj, csrfToken } }
    }
    return { ok: false, error: new Error('Failed to decrypt') }
  } catch (e) {
    return { ok: false, error: e }
  }
}
