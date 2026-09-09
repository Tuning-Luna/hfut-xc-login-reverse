"""HFUT 统一身份认证（CAS）及门户 / 教务子系统的逆向登录客户端。

本模块由原根目录 reverse.py 迁移而来，保留类名 ``Reverse`` 与全部接口，
仅将重复请求头抽取到 hfut.headers，并补充缺失的 @staticmethod 标注。
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
from typing import Optional

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from hfut import config, headers


class Reverse:
    session = requests.Session()
    # 全局保存 code 和 token
    code = None
    token = None

    SESSION_FILE = config.SESSION_FILE

    # -------- 会话持久化工具方法 --------
    @staticmethod
    def save_session(file_path: Optional[str] = None) -> None:
        """将当前 session cookies、token、code 持久化到本地文件"""
        if file_path is None:
            file_path = Reverse.SESSION_FILE

        data = {
            "token": Reverse.token,
            "code": Reverse.code,
            "cookies": [
                {
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                }
                for c in Reverse.session.cookies
            ],
        }

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            # 持久化失败不应影响主流程，打印一下即可
            print("保存会话信息失败：", e)

    @staticmethod
    def load_session(file_path: Optional[str] = None) -> bool:
        """从本地文件恢复 session cookies、token、code 并校验，成功返回 True"""
        if file_path is None:
            file_path = Reverse.SESSION_FILE

        if not os.path.exists(file_path):
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print("读取会话信息失败：", e)
            return False

        # 恢复 token / code
        Reverse.token = data.get("token")
        Reverse.code = data.get("code")

        # 恢复 cookies
        Reverse.session.cookies.clear()
        for c in data.get("cookies", []):
            try:
                Reverse.session.cookies.set(
                    c.get("name"),
                    c.get("value"),
                    domain=c.get("domain"),
                    path=c.get("path") or "/",
                )
            except Exception:
                continue

        # 如果有 token 和 code，则尝试校验一次
        if Reverse.token and Reverse.code:
            try:
                if Reverse.checkToken(Reverse.token, Reverse.code):
                    print("已从本地会话文件恢复登录状态。")
                    return True
            except Exception as e:
                print("本地会话校验失败，将视为未登录：", e)
                return False

        return False

    # 获取SESSION
    @staticmethod
    def preLogin() -> requests.Response:
        url = f"{config.CAS_BASE}/cas/login"
        params = {
            "service": (
                "https://cas.hfut.edu.cn/cas/oauth2.0/callbackAuthorize"
                "?client_id=BsHfutEduPortal"
                "&redirect_uri=https%3A%2F%2Fone.hfut.edu.cn%2Fhome%2Findex"
                "&response_type=code&client_name=CasOAuthClient"
            )
        }
        response = Reverse.session.get(
            url,
            headers=headers.page(
                extra={
                    "Cache-Control": "max-age=0",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                }
            ),
            params=params,
        )
        return response

    # 获取JSSESSIONID
    @staticmethod
    def vercode() -> requests.Response:
        url = f"{config.CAS_BASE}/cas/vercode"

        response = Reverse.session.get(url, headers=headers.image())
        return response

    # 获取LOGIN_FLAVORING
    @staticmethod
    def checkInitParams() -> requests.Response:
        url = f"{config.CAS_BASE}/cas/checkInitParams"
        params = {"_": str(int(time.time() * 1000))}
        response = Reverse.session.get(
            url, headers=headers.cas_xhr_json(), params=params
        )
        return response

    # 获取验证码
    @staticmethod
    def vercodeWithTime() -> requests.Response:
        url = f"{config.CAS_BASE}/cas/vercode"
        params = {"time": str(int(time.time() * 1000))}
        response = Reverse.session.get(
            url, headers=headers.image(), params=params
        )
        return response

    #  ------- 初始化结束 -------

    # 按下登录后
    @staticmethod
    def checkUserIdenty(capcha) -> requests.Response:
        url = f"{config.CAS_BASE}/cas/policy/checkUserIdenty"
        params = {
            "username": config.STUDENT_ID,
            "password": Reverse.encryption_pwd(),
            "capcha": capcha,
            "_": str(int(time.time() * 1000)),
        }
        response = Reverse.session.get(
            url, headers=headers.cas_xhr_json(), params=params
        )
        return response

    # 加密
    @staticmethod
    def encryption_pwd() -> str:
        key = Reverse.session.cookies.get_dict()["LOGIN_FLAVORING"].encode("utf-8")

        # 不要修改全局的 password
        pwd_bytes = config.PASSWORD.encode("utf-8")

        if len(key) not in (16, 24, 32):
            raise ValueError("密钥长度必须为 16、24 或 32 字节（对应 AES-128/192/256）")

        padded_password = pad(pwd_bytes, AES.block_size)

        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(padded_password)

        encrypted_pwd = base64.b64encode(encrypted).decode("utf-8")
        return encrypted_pwd

    # 登录,拿到TGC，进行一系列的302跳转
    @staticmethod
    def login(capcha) -> requests.Response:
        url = f"{config.CAS_BASE}/cas/login"
        params = {
            "service": (
                "https://cas.hfut.edu.cn/cas/oauth2.0/callbackAuthorize"
                "?client_id=BsHfutEduPortal"
                "&redirect_uri=https%3A%2F%2Fone.hfut.edu.cn%2Fhome%2Findex"
                "&response_type=code&client_name=CasOAuthClient"
            )
        }
        data = {
            "username": config.STUDENT_ID,
            "capcha": capcha,
            "execution": "e1s1",
            "_eventId": "submit",
            "password": Reverse.encryption_pwd(),
            "geolocation": "",
        }

        response = Reverse.session.post(
            url,
            headers=headers.page(
                extra={
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": config.CAS_BASE,
                    "Referer": config.CAS_LOGIN_REFERER,
                    "Sec-Fetch-User": "?1",
                }
            ),
            params=params,
            data=data,
        )
        return response

    # 调试链方法
    @staticmethod
    def send_debug(
        session: requests.Session, method, url, allow_redirects=True, **kwargs
    ):
        resp = session.request(method, url, allow_redirects=allow_redirects, **kwargs)

        print("\n====== 当前请求 & 响应 ======")
        print(f"[{method.upper()}] {resp.status_code} {resp.url}")

        # 本次请求发出去的 Cookie
        req_cookie = resp.request.headers.get("Cookie")
        print("  >>> 请求发送的 Cookie:", req_cookie if req_cookie else "{}")

        if "Location" in resp.headers:
            print("  >>> 响应 Location:", resp.headers["Location"])

        print("  >>> 响应 Set-Cookie:", resp.headers.get("Set-Cookie"))

        print("  >>> 当前 session cookies:", session.cookies.get_dict())

        print()

        # 只有开启了自动重定向，才打印完整历史链（你原来想要的效果）
        if allow_redirects and resp.history:
            print("====== 完整重定向链条 ======")
            for i, h in enumerate(resp.history, 1):
                print(f"[{i}] {h.status_code} {h.url}")

                print("  >>> 请求发送的 Cookie：")
                print("  ", h.request.headers.get("Cookie"))

                print("  >>> 响应返回的 Set-Cookie：")
                print("  ", h.headers.get("Set-Cookie"))

                print()

            print("====== 最终响应 ======")
            print(resp.status_code, resp.url)
            print("Set-Cookie:", resp.headers.get("Set-Cookie"))
            print()

        print("====== 结束 ======")
        return resp

    # 调试单个请求方法
    @staticmethod
    def debug_response(resp: requests.Response) -> None:
        print("\n====== 调试单个 Response ======")

        print(f"状态码: {resp.status_code}")
        print(f"URL: {resp.url}")

        # 请求发送的 Cookie
        req_cookie = resp.request.headers.get("Cookie")
        print("请求发送的 Cookie:", req_cookie if req_cookie else "{}")

        # 响应 Set-Cookie
        set_cookie = resp.headers.get("Set-Cookie")
        print("响应 Set-Cookie:", set_cookie if set_cookie else "{}")

        # Location
        if "Location" in resp.headers:
            print("响应 Location:", resp.headers["Location"])

        print("====== 结束 ======\n")

    # 生成 secret 密钥
    @staticmethod
    def generate_secret() -> str:
        # token_hex(8) 产生 8 字节（16 hex 字符），upper() 变为大写
        return secrets.token_hex(8).upper()

    # 通过 secret Cookie 以及302后的查询参数Code 获取 Token Cookie
    @staticmethod
    def authorize() -> requests.Response:
        url = f"{config.CAS_BASE}/cas/oauth2.0/authorize"
        params = {
            "response_type": "code",
            "client_id": "BsHfutEduPortal",
            "redirect_uri": f"{config.ONE_BASE}/home/index",
        }

        response = Reverse.session.get(
            url,
            headers=headers.page(
                extra={
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "Referer": config.CAS_AUTHORIZE_REFERER,
                }
            ),
            params=params,
        )
        return response

    # 获得token
    @staticmethod
    def getToken(code) -> requests.Response:
        url = f"{config.ONE_BASE}/api/auth/oauth/getToken"

        params = {
            "type": "portal",
            "redirect": (
                "https%3A//one.hfut.edu.cn/home/index%3Fcode%3D"
                "OC-37243-Pe4GLnCpdAWU7V7aK2BjUWnxexJ4fhVh"
            ),
            "code": code,
        }
        response = Reverse.session.get(
            url,
            headers=headers.xhr_json(
                extra={
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "Referer": f"{config.ONE_HOME_INDEX}?code={code}",
                }
            ),
            params=params,
        )
        return response

    # 检查token合法（查询参数和cookie是同一个token，都要携带），返回boolean
    @staticmethod
    def checkToken(token, code) -> bool:
        url = f"{config.ONE_BASE}/cas/bosssoft/checkToken"
        params = {"token": token}

        response = Reverse.session.get(
            url,
            headers=headers.xhr_json(
                extra={
                    "Authorization": "Bearer " + token,
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "Referer": f"{config.ONE_HOME_INDEX}?code={code}",
                }
            ),
            params=params,
        )

        if response.json()["data"]:
            return True
        else:
            raise Exception("token不合法")

    # ------ 主站逆向结束 ------

    # 查询用户基本信息
    @staticmethod
    def selectUserSimplifyInfoForHall(token, code) -> requests.Response:
        url = f"{config.ONE_BASE}/api/center/user/selectUserSimplifyInfoForHall"

        response = Reverse.session.get(
            url,
            headers=headers.xhr_json(
                extra={
                    "Authorization": "Bearer " + token,
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "Referer": f"{config.ONE_HOME_INDEX}?code={code}",
                }
            ),
        )
        return response

    # 查询用户稍微敏感信息
    @staticmethod
    def selectUserInfoForHall(token) -> requests.Response:
        url = f"{config.ONE_BASE}/api/center/user/selectUserInfoForHall"

        response = Reverse.session.get(
            url,
            headers=headers.xhr_json(
                extra={
                    "Authorization": "Bearer " + token,
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "Referer": config.ONE_HOME_INDEX,
                }
            ),
        )
        return response

    # ------ 逆向学生教务系统（子系统） ------

    # 访问首页，获得新的SESSON和SRVID
    @staticmethod
    def studentHome() -> requests.Response:
        r1 = Reverse.session.get(
            config.EAMS_HOME,
            headers=headers.eams_page(),
            verify=config.EAMS_VERIFY_SSL,
        )
        return r1

    # 登录
    @staticmethod
    def studentLogin() -> requests.Response:
        url = f"{config.EAMS_BASE}/eams5-student/neusoft-sso/login"
        response = Reverse.session.get(
            url,
            headers=headers.eams_page(
                extra={"Referer": config.EAMS_LOGIN_REFERER}
            ),
        )
        return response

    # ----- 逆向教务系统（子系统）结束 -----

    # 测试，查询某个敏感数据（成绩）
    @staticmethod
    def programCompletionPreview() -> requests.Response:
        url = (
            f"{config.EAMS_BASE}/eams5-student/ws/student/home-page/"
            "programCompletionPreview"
        )

        response = Reverse.session.get(
            url,
            headers=headers.eams_json(extra={"Referer": config.EAMS_HOME}),
        )
        return response

    # 查询考试安排信息，返回html
    @staticmethod
    def examrrangeInfo() -> requests.Response:
        url = (
            f"{config.EAMS_BASE}/eams5-student/for-std/exam-arrange/info/169061"
        )
        response = Reverse.session.get(
            url,
            headers=headers.eams_page(extra={"Referer": config.EAMS_HOME}),
            verify=config.EAMS_VERIFY_SSL,
        )
        return response

