import axios from "../tools/request"

export function checkInitParams() {
  // 生成当前时间戳
  const timestamp = new Date().getTime()
  return axios.get("https://cas.hfut.edu.cn/cas/checkInitParams", {
    params: {
      _: timestamp,
    },
    headers: {
      Accept: "application/json, text/javascript, */*; q=0.01",
      "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
      Connection: "keep-alive",
      Referer:
        "https://cas.hfut.edu.cn/cas/login?service=https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DBsHfutEduPortal%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex%26response_type%3Dcode%26client_name%3DCasOAuthClient",
      "Sec-Fetch-Dest": "empty",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "same-origin",
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
      "X-Requested-With": "XMLHttpRequest",
      "sec-ch-ua":
        '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
      // 此处Cookie可省略，因为在创建axios实例对象时已经处理携带Cookie
      Cookie:
        "SESSION=54c76b92-2ab7-4ea1-9a25-5ced6af154f1; JSESSIONID=8a348ee0a21940e7b65767f22b01a25b",
    },
  })
}
