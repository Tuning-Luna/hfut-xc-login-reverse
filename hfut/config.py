"""全局配置：账号信息与各子系统接口常量。

账号信息来自项目根目录的 .env 文件（仅本地读取，不会上传）。
URL / Referer 等常量集中于此，避免在各请求方法中重复书写。
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# 账号来自项目根目录的 .env 或环境变量，登录前校验是否完整。
STUDENT_ID = os.getenv("student_id")
PASSWORD = os.getenv("password")


def validate_credentials() -> None:
    """检查登录必需的配置，错误信息只包含字段名，不包含凭据。"""
    missing = [
        name
        for name, value in (("student_id", STUDENT_ID), ("password", PASSWORD))
        if not value
    ]
    if missing:
        raise ValueError(
            f"缺少账号配置：{', '.join(missing)}。"
            "请在项目根目录的 .env 文件中填写 student_id 和 password"
            "（参考 .env.example），保存后重新启动程序。"
        )


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
