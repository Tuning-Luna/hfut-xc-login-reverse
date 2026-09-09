"""全局配置：账号信息与各子系统接口常量。

账号信息来自项目根目录的 .env 文件（仅本地读取，不会上传）。
URL / Referer 等常量集中于此，避免在各请求方法中重复书写。
"""

import os

from dotenv import load_dotenv

load_dotenv()

# 账号（来自 .env，保持与旧 reverse.py 一致：可能为 None，由调用方决定如何处理）
STUDENT_ID = os.getenv("student_id")
PASSWORD = os.getenv("password")

# 会话持久化文件名
SESSION_FILE = "session.json"

# 各子系统根地址
CAS_BASE = "https://cas.hfut.edu.cn"
ONE_BASE = "https://one.hfut.edu.cn"
EAMS_BASE = "http://jxglstu.hfut.edu.cn"

# 教务系统为 http 明文，关闭 SSL 校验
EAMS_VERIFY_SSL = False

# CAS 登录页（带 service 参数），多数 CAS 请求以此为 Referer
CAS_LOGIN_REFERER = (
    "https://cas.hfut.edu.cn/cas/login?service="
    "https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize"
    "%3Fclient_id%3DBsHfutEduPortal"
    "%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex"
    "%26response_type%3Dcode%26client_name%3DCasOAuthClient"
)

# OAuth 授权页（authorize 请求的 Referer）
CAS_AUTHORIZE_REFERER = (
    "https://cas.hfut.edu.cn/cas/oauth2.0/authorize"
    "?response_type=code&client_id=BsHfutEduPortal"
    "&redirect_uri=https%3A//one.hfut.edu.cn/home/index"
)

# 教务系统（eams）页面地址
EAMS_HOME = f"{EAMS_BASE}/eams5-student/home"
EAMS_LOGIN_REFERER = f"{EAMS_BASE}/eams5-student/login?refer={EAMS_HOME}"

# 门户首页（带 code 时用于查询类接口的 Referer）
ONE_HOME_INDEX = f"{ONE_BASE}/home/index"
