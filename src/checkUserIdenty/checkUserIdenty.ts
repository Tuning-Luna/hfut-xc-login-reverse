import { encryptionPwd } from "../tools/encryptionPwd"
import axios from "../tools/request"

export function checkUserIdenty(
  username: string,
  password: string,
  capcha: string
) {
  const _ = new Date().getTime()
  return axios.get("https://cas.hfut.edu.cn/cas/policy/checkUserIdenty", {
    params: {
      username: username,
      password: encryptionPwd(password),
      capcha: capcha,
      _: _,
    },
    headers: {
      "sec-ch-ua-platform": '"Windows"',
      Referer:
        "https://cas.hfut.edu.cn/cas/login?service=https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DBsHfutEduPortal%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex%26response_type%3Dcode%26client_name%3DCasOAuthClient",
      "X-Requested-With": "XMLHttpRequest",
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
      Accept: "application/json, text/javascript, */*; q=0.01",
      "sec-ch-ua":
        '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
    },
  })
}
