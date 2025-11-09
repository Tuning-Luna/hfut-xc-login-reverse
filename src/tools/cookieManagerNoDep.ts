// cookieManager.ts
import type {
  AxiosInstance,
  InternalAxiosRequestConfig,
  AxiosResponse,
} from "axios"

// 内存 Cookie 存储
export const cookieStore: Record<string, string> = {}

export const JSESSIONID: string = "JSESSIONID"
export const LOGIN_FLAVORING: string = "LOGIN_FLAVORING"
export const SESSION: string = "SESSION"

// 解析 Set-Cookie，只取 name=value
export function parseSetCookie(setCookieArr: string[]) {
  for (const cookie of setCookieArr) {
    // 形如 "SESSION=abc123; Path=/; HttpOnly"
    const [nameValue] = cookie.split(";")
    const [name, value] = nameValue!.split("=")
    if (name && value) {
      cookieStore[name.trim()] = value.trim()
    }
  }
}

// 拼接 Cookie 字符串：name=value; name2=value2
export function getCookieHeader() {
  return Object.entries(cookieStore)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ")
}

export function hasAllCookies() {
  return (
    !!cookieStore[JSESSIONID] &&
    !!cookieStore[LOGIN_FLAVORING] &&
    !!cookieStore[SESSION]
  )
}

export function getCookie(name: string) {
  return cookieStore[name]
}

// ---- axios hooks ---- //
// #region
async function attachCookies(
  config: InternalAxiosRequestConfig
): Promise<InternalAxiosRequestConfig> {
  const cookieString = getCookieHeader()

  if (cookieString) {
    config.headers = {
      ...(config.headers || {}),
      Cookie: cookieString,
    } as any
  }
  return config
}

async function storeCookies(response: AxiosResponse) {
  const setCookie = response.headers["set-cookie"]
  if (setCookie) {
    parseSetCookie(setCookie)
  }
  return response
}

export function setupAxiosCookie(instance: AxiosInstance) {
  instance.interceptors.request.use((config) => attachCookies(config))

  instance.interceptors.response.use((response) => storeCookies(response))

  return instance
}

export default { setupAxiosCookie }

// #endregion
