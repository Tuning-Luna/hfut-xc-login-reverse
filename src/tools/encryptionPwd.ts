import CryptoJS from "crypto-js"
import { getCookie, LOGIN_FLAVORING } from "./cookieManagerNoDep"

export function encryptionPwd(pwd: string) {
  const secretKey = getCookie(LOGIN_FLAVORING)
  const key = CryptoJS.enc.Utf8.parse(secretKey!)
  const password = CryptoJS.enc.Utf8.parse(pwd)

  const encrypted = CryptoJS.AES.encrypt(password, key, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  })

  return encrypted.toString()
}
