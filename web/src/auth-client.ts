import { AuthClient } from '@redwoodjs/auth/dist/authClients'

interface LoginAttributes {
  username: string
  password: string
}

interface ResetPasswordAttributes {
  token: string
  password: string
}

type SignupAttributes = Record<string, unknown> & LoginAttributes

type AuthConfig = {
  fetchConfig: {
    credentials: 'include' | 'same-origin'
  }
}
const TOKEN_CACHE_TIME = 5000

let getTokenPromise: null | Promise<string | null>
let lastTokenCheckAt = new Date('1970-01-01T00:00:00')
let cachedToken: string | null

export const authClient = (
  config: AuthConfig = { fetchConfig: { credentials: 'same-origin' } }
): AuthClient => {
  const { credentials } = config.fetchConfig

  const resetAndFetch = async (...params: Parameters<typeof fetch>) => {
    resetTokenCache()
    return fetch(...params)
  }

  const isTokenCacheExpired = () => {
    const now = new Date()
    return now.getTime() - lastTokenCheckAt.getTime() > TOKEN_CACHE_TIME
  }

  const resetTokenCache = () => {
    lastTokenCheckAt = new Date('1970-01-01T00:00:00')
    cachedToken = null
  }

  const forgotPassword = async (username: string) => {
    const response = await resetAndFetch(global.RWJS_API_DBAUTH_URL, {
      credentials,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, method: 'forgotPassword' }),
    })

    return await response.json()
  }

  const getToken = async () => {
    // Return the existing fetch promise, so that parallel calls
    // to getToken only cause a single fetch
    if (getTokenPromise) {
      return getTokenPromise
    }

    if (isTokenCacheExpired()) {
      getTokenPromise = fetch(`${global.RWJS_API_DBAUTH_URL}?method=getToken`, {
        credentials,
      })
        .then((response) => response.text())
        .then((tokenText) => {
          lastTokenCheckAt = new Date()
          getTokenPromise = null
          cachedToken = tokenText.length === 0 ? null : tokenText

          return cachedToken
        })

      return getTokenPromise
    }

    return cachedToken
  }

  const login = async (attributes: LoginAttributes) => {
    const { username, password } = attributes
    const response = await resetAndFetch(global.RWJS_API_DBAUTH_URL, {
      credentials,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, method: 'login' }),
    })

    return await response.json()
  }

  const logout = async () => {
    await resetAndFetch(global.RWJS_API_DBAUTH_URL, {
      credentials,
      method: 'POST',
      body: JSON.stringify({ method: 'logout' }),
    })

    return true
  }

  const resetPassword = async (attributes: ResetPasswordAttributes) => {
    const response = await resetAndFetch(global.RWJS_API_DBAUTH_URL, {
      credentials,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...attributes, method: 'resetPassword' }),
    })

    return await response.json()
  }

  const signup = async (attributes: SignupAttributes) => {
    const response = await resetAndFetch(global.RWJS_API_DBAUTH_URL, {
      credentials,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...attributes, method: 'signup' }),
    })

    return await response.json()
  }

  const validateResetToken = async (resetToken: string | null) => {
    const response = await resetAndFetch(global.RWJS_API_DBAUTH_URL, {
      credentials,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resetToken, method: 'validateResetToken' }),
    })

    return await response.json()
  }

  return {
    type: 'custom',
    client: {},
    login,
    logout,
    signup,
    getToken,
    getUserMetadata: getToken,
    forgotPassword,
    resetPassword,
    validateResetToken,
  }
}
