export function jsonSafeParse<T = Record<string, unknown>>(
  input: string
): TResult<T, Error> {
  try {
    return { ok: true, data: JSON.parse(input) as T }
  } catch (e) {
    return { ok: false, error: e }
  }
}
