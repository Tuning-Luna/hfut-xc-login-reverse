"""独立验证码抓取工具（可用于收集样本 / 人工标注）。

会先访问一次 CAS 登录页以建立会话 Cookie（SESSION / JSESSIONID），
然后按固定间隔循环抓取验证码图片保存到 ./vercode 目录。

用法：
    python vercode.py
"""

import time
from pathlib import Path

import requests

from hfut import config, headers

# 验证码接口
VERCODE_URL = f"{config.CAS_BASE}/cas/vercode"

# 保存目录
SAVE_DIR = Path("./vercode")
SAVE_DIR.mkdir(exist_ok=True)

# 请求间隔秒数
INTERVAL = 3  # 你可以自定义，比如 1 秒请求一次

# 登录页 service 参数（与主流程一致）
_SERVICE = (
    "https://cas.hfut.edu.cn/cas/oauth2.0/callbackAuthorize"
    "?client_id=BsHfutEduPortal"
    "&redirect_uri=https%3A%2F%2Fone.hfut.edu.cn%2Fhome%2Findex"
    "&response_type=code&client_name=CasOAuthClient"
)


def warmup_session(session: requests.Session) -> None:
    """访问一次 CAS 登录页，让服务端下发 SESSION / JSESSIONID Cookie。

    验证码校验依赖该会话，因此需要与登录页共用同一个 session。
    """
    session.get(
        f"{config.CAS_BASE}/cas/login",
        headers=headers.page(extra={"Sec-Fetch-Site": "none"}),
        params={"service": _SERVICE},
    )


def fetch_vercode(session: requests.Session) -> None:
    ts = int(time.time() * 1000)  # 时间戳（毫秒）
    params = {"time": str(ts)}

    resp = session.get(VERCODE_URL, headers=headers.image(), params=params)

    if resp.status_code == 200 and resp.content:
        filename = SAVE_DIR / f"{ts}.png"
        filename.write_bytes(resp.content)
        print(f"[OK] 验证码保存成功: {filename}")
    else:
        print(f"[ERR] 请求失败: HTTP {resp.status_code}")


def loop_fetch() -> None:
    session = requests.Session()
    warmup_session(session)

    while True:
        fetch_vercode(session)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    print("开始持续获取验证码...")
    loop_fetch()
