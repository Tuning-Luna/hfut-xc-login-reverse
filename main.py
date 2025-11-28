from random import random
import requests
import time
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from dotenv import load_dotenv
import secrets
from urllib.parse import urlparse, parse_qs

load_dotenv()
student_id = os.getenv("student_id")
password = os.getenv("password")

# student_id = input("请输入学号：")
# password = input("请输入密码：")


class Reverse:
    session = requests.Session()

    # 获取SESSION
    @staticmethod
    def preLogin() -> requests.Response:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://cas.hfut.edu.cn/cas/login"
        params = {
            "service": "https://cas.hfut.edu.cn/cas/oauth2.0/callbackAuthorize?client_id=BsHfutEduPortal&redirect_uri=https%3A%2F%2Fone.hfut.edu.cn%2Fhome%2Findex&response_type=code&client_name=CasOAuthClient"
        }
        response = Reverse.session.get(url, headers=headers, params=params)
        return response

    # 获取JSSESSIONID
    @staticmethod
    def vercode() -> requests.Response:
        headers = {
            "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Connection": "keep-alive",
            "Referer": "https://cas.hfut.edu.cn/cas/login?service=https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DBsHfutEduPortal%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex%26response_type%3Dcode%26client_name%3DCasOAuthClient",
            "Sec-Fetch-Dest": "image",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://cas.hfut.edu.cn/cas/vercode"

        response = Reverse.session.get(url, headers=headers)
        return response

    # 获取LOGIN_FLAVORING
    @staticmethod
    def checkInitParams() -> requests.Response:
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Connection": "keep-alive",
            "Referer": "https://cas.hfut.edu.cn/cas/login?service=https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DBsHfutEduPortal%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex%26response_type%3Dcode%26client_name%3DCasOAuthClient",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "X-Requested-With": "XMLHttpRequest",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://cas.hfut.edu.cn/cas/checkInitParams"
        params = {"_": str(int(time.time() * 1000))}
        response = Reverse.session.get(url, headers=headers, params=params)
        return response

    # 获取验证码
    @staticmethod
    def vercodeWithTime() -> requests.Response:
        headers = {
            "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Connection": "keep-alive",
            "Referer": "https://cas.hfut.edu.cn/cas/login?service=https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DBsHfutEduPortal%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex%26response_type%3Dcode%26client_name%3DCasOAuthClient",
            "Sec-Fetch-Dest": "image",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://cas.hfut.edu.cn/cas/vercode"
        params = {"time": str(int(time.time() * 1000))}
        response = Reverse.session.get(url, headers=headers, params=params)
        return response

    #  ------- 初始化结束 -------

    # 按下登录后
    def checkUserIdenty(capcha) -> requests.Response:
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Connection": "keep-alive",
            "Referer": "https://cas.hfut.edu.cn/cas/login?service=https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DBsHfutEduPortal%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex%26response_type%3Dcode%26client_name%3DCasOAuthClient",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "X-Requested-With": "XMLHttpRequest",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://cas.hfut.edu.cn/cas/policy/checkUserIdenty"
        params = {
            "username": student_id,
            "password": Reverse.encryption_pwd(),
            "capcha": capcha,
            "_": str(int(time.time() * 1000)),
        }
        response = Reverse.session.get(url, headers=headers, params=params)
        return response

    # 加密
    @staticmethod
    def encryption_pwd() -> str:
        key = Reverse.session.cookies.get_dict()["LOGIN_FLAVORING"].encode("utf-8")

        # 不要修改全局的 password
        pwd_bytes = password.encode("utf-8")

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
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://cas.hfut.edu.cn",
            "Referer": "https://cas.hfut.edu.cn/cas/login?service=https%3A%2F%2Fcas.hfut.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DBsHfutEduPortal%26redirect_uri%3Dhttps%253A%252F%252Fone.hfut.edu.cn%252Fhome%252Findex%26response_type%3Dcode%26client_name%3DCasOAuthClient",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://cas.hfut.edu.cn/cas/login"
        params = {
            "service": "https://cas.hfut.edu.cn/cas/oauth2.0/callbackAuthorize?client_id=BsHfutEduPortal&redirect_uri=https%3A%2F%2Fone.hfut.edu.cn%2Fhome%2Findex&response_type=code&client_name=CasOAuthClient"
        }
        data = {
            "username": student_id,
            "capcha": capcha,
            "execution": "e1s1",
            "_eventId": "submit",
            "password": Reverse.encryption_pwd(),
            "geolocation": "",
        }

        # 注释掉的有完整调试链

        # response = Reverse.send_debug(
        #     Reverse.session,
        #     "POST",
        #     url,
        #     headers=headers,
        #     params=params,
        #     data=data,
        # )

        response = Reverse.session.post(url, headers=headers, params=params, data=data)
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
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Referer": "https://cas.hfut.edu.cn/cas/oauth2.0/authorize?response_type=code&client_id=BsHfutEduPortal&redirect_uri=https%3A//one.hfut.edu.cn/home/index",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://cas.hfut.edu.cn/cas/oauth2.0/authorize"
        params = {
            "response_type": "code",
            "client_id": "BsHfutEduPortal",
            "redirect_uri": "https://one.hfut.edu.cn/home/index",
        }

        # 注释掉的有完整请求链

        # response = Reverse.send_debug(
        #     Reverse.session,
        #     "GET",
        #     url,
        #     headers=headers,
        #     params=params,
        # )

        response = Reverse.session.get(url, headers=headers, params=params)
        return response

    # 获得token
    @staticmethod
    def getToken(code) -> str:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Referer": "https://one.hfut.edu.cn/home/index?code=" + code,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://one.hfut.edu.cn/api/auth/oauth/getToken"

        params = {
            "type": "portal",
            "redirect": "https%3A//one.hfut.edu.cn/home/index%3Fcode%3DOC-37243-Pe4GLnCpdAWU7V7aK2BjUWnxexJ4fhVh",
            "code": code,
        }
        response = Reverse.session.get(url, headers=headers, params=params)
        return response

    # 检查token合法（查询参数和cookie是同一个token，都要携带），返回boolean
    @staticmethod
    def checkToken(token, code) -> bool:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Authorization": "Bearer " + token,
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Referer": "https://one.hfut.edu.cn/home/index?code=" + code,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://one.hfut.edu.cn/cas/bosssoft/checkToken"
        params = {"token": token}

        response = Reverse.session.get(url, headers=headers, params=params)

        if response.json()["data"]:
            return True
        else:
            raise Exception("token不合法")

    # ------ 主站逆向结束 ------

    # 查询用户基本信息
    @staticmethod
    def selectUserSimplifyInfoForHall(token, code) -> requests.Response:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Authorization": "Bearer " + token,
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Referer": "https://one.hfut.edu.cn/home/index?code=" + code,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://one.hfut.edu.cn/api/center/user/selectUserSimplifyInfoForHall"

        response = Reverse.session.get(url, headers=headers)
        return response

    # 查询用户稍微敏感信息
    @staticmethod
    def selectUserInfoForHall(token) -> requests.Response:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Authorization": "Bearer " + token,
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Referer": "https://one.hfut.edu.cn/home/index",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        url = "https://one.hfut.edu.cn/api/center/user/selectUserInfoForHall"

        response = Reverse.session.get(url, headers=headers)
        return response

    # ------ 逆向学生教务系统（子系统） ------

    # 访问首页，获得新的SESSON和SRVID
    def studentHome() -> requests.Response:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Proxy-Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        }
        url = "http://jxglstu.hfut.edu.cn/eams5-student/home"

        r1 = Reverse.session.get(url, headers=headers, verify=False)
        # r1 = Reverse.send_debug(
        #     Reverse.session, "GET", url, headers=headers, verify=False
        # )
        return r1

    # 登录
    def studentLogin() -> requests.Response:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Proxy-Connection": "keep-alive",
            "Referer": "http://jxglstu.hfut.edu.cn/eams5-student/login?refer=http://jxglstu.hfut.edu.cn/eams5-student/home",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        }
        url = "http://jxglstu.hfut.edu.cn/eams5-student/neusoft-sso/login"
        response = Reverse.session.get(url, headers=headers)

        # response = Reverse.send_debug(
        #     Reverse.session, "GET", url, headers=headers, verify=False
        # )
        return response

    # ----- 逆向教务系统（子系统）结束 -----

    # 测试，查询某个敏感数据（成绩）
    def programCompletionPreview() -> requests.Response:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Proxy-Connection": "keep-alive",
            "Referer": "http://jxglstu.hfut.edu.cn/eams5-student/home",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        }
        url = "http://jxglstu.hfut.edu.cn/eams5-student/ws/student/home-page/programCompletionPreview"

        response = Reverse.session.get(url, headers=headers)
        return response


def ensure_credentials():
    """确保学号与密码已加载，环境变量缺失时转为交互输入。"""
    global student_id, password
    if not student_id:
        student_id = input("请输入学号：").strip()
    if not password:
        password = input("请输入密码：").strip()


class ReverseCLI:
    """面向命令行的交互逻辑封装，爬虫请求仍复用 Reverse 类。"""

    def __init__(self):
        self.token = None
        self.code = None
        self.vercode_file = "vercode.png"

    def _prepare_login_chain(self):
        Reverse.preLogin()
        Reverse.vercode()
        Reverse.checkInitParams()
        return Reverse.vercodeWithTime()

    def _save_and_open_captcha(self, response):
        with open(self.vercode_file, "wb") as f:
            f.write(response.content)
        try:
            os.startfile(self.vercode_file)
        except Exception:
            print(f"验证码已保存至 {self.vercode_file}，请手动打开查看。")

    def login(self):
        print("正在初始化登录链路...")
        res = self._prepare_login_chain()
        self._save_and_open_captcha(res)

        vercode = input("请输入验证码：").strip()
        Reverse.checkUserIdenty(vercode)

        secret = Reverse.generate_secret()
        Reverse.session.cookies.set(
            "secret", secret, domain="one.hfut.edu.cn", path="/"
        )

        Reverse.authorize()
        Reverse.login(vercode)
        res_final = Reverse.authorize()

        parsed = urlparse(res_final.url)
        params = parse_qs(parsed.query)
        self.code = params.get("code", [None])[0]
        if not self.code:
            raise RuntimeError("未能在重定向中解析到 code")
        print("code:", self.code)

        res_token = Reverse.getToken(self.code)
        self.token = res_token.json()["data"]["access_token"]
        print("token:", self.token)

        Reverse.session.cookies.set(
            "token", self.token, domain="one.hfut.edu.cn", path="/"
        )
        Reverse.checkToken(self.token, self.code)
        print("登录成功，token 已写入会话。")

    def _require_token(self):
        if not self.token or not self.code:
            print("请先完成登录获取 token。")
            return False
        return True

    def fetch_basic_info(self):
        if not self._require_token():
            return
        res = Reverse.selectUserSimplifyInfoForHall(self.token, self.code)
        print("用户简要信息：", res.json())

    def fetch_detail_info(self):
        if not self._require_token():
            return
        res = Reverse.selectUserInfoForHall(self.token)
        print("用户详细信息：", res.json())

    def fetch_grades(self):
        if not self._require_token():
            return
        Reverse.studentHome()
        Reverse.studentLogin()
        res = Reverse.programCompletionPreview()
        print("成绩信息：", res.json())

    def show_menu(self):
        print(
            "\n请选择操作：\n"
            "1. 登录并获取 token\n"
            "2. 查询用户简要信息\n"
            "3. 查询用户详细信息\n"
            "4. 查询课程完成情况（成绩）\n"
            "5. 退出\n"
        )


def main():
    ensure_credentials()
    cli = ReverseCLI()

    action_map = {
        "1": cli.login,
        "2": cli.fetch_basic_info,
        "3": cli.fetch_detail_info,
        "4": cli.fetch_grades,
    }

    while True:
        cli.show_menu()
        choice = input("输入序号：").strip()
        if choice == "5":
            print("已退出。")
            break
        action = action_map.get(choice)
        if action:
            try:
                action()
            except Exception as exc:
                print("操作失败：", exc)
        else:
            print("无效输入，请重新选择。")


if __name__ == "__main__":
    main()
