import requests
import time
import os

# 固定请求头
headers = {
    "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "Referer": "https://cas.hfut.edu.cn/cas/login?service=https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DBsHfutEduPortal%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex%26response_type%3Dcode%26client_name%3DCasOAuthClient",
    "Sec-Fetch-Dest": "image",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

# 固定 Cookie（你可以外部获取后动态写入）
cookies = {
    "SESSION": "60ba9476-779c-4d7d-a783-277b0b4e7bce",
    "JSESSIONID": "5829dac1c639474e9673308473e8443c",
    "LOGIN_FLAVORING": "6lc1cw5bk2hcd845",
}

# 验证码接口
url = "https://cas.hfut.edu.cn/cas/vercode"

# 保存目录
save_path = "./vercode"
os.makedirs(save_path, exist_ok=True)

# 请求间隔秒数
interval = 3  # 你可以自定义，比如 1 秒请求一次


def fetch_vercode():
    ts = int(time.time() * 1000)  # 时间戳（毫秒）
    params = {"time": str(ts)}

    resp = requests.get(url, headers=headers, cookies=cookies, params=params)

    if resp.status_code == 200 and resp.content:
        filename = f"{save_path}/{ts}.png"
        with open(filename, "wb") as f:
            f.write(resp.content)
        print(f"[OK] 验证码保存成功: {filename}")
    else:
        print(f"[ERR] 请求失败: HTTP {resp.status_code}")


def loop_fetch():
    while True:
        fetch_vercode()
        time.sleep(interval)


if __name__ == "__main__":
    print("开始持续获取验证码...")
    loop_fetch()
