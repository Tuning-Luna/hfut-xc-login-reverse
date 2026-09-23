"""HFUT 登录逆向 CLI 入口。

用法：
    python main.py
"""

import threading
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup
from tabulate import tabulate

from hfut import config, log
from hfut.client import Reverse

# 入口脚本用固定的 logger 名，避免以脚本运行时显示为 __main__
logger = log.get_logger("cli")

# 在模块导入时配置日志：UserCLI 也会被测试直接导入调用，需要一致的输出行为
log.setup_logging()

# 验证码图片的保存位置（相对当前工作目录）
VERCODE_FILE = Path("vercode.png")


class UserCLI:
    # 初始化用户
    @staticmethod
    def init() -> bool:
        # 如果可以从本地文件恢复会话，就直接返回，不再走验证码登录流程
        if Reverse.load_session():
            return True

        config.validate_credentials()
        Reverse.preLogin()
        Reverse.vercode()
        Reverse.checkInitParams()
        res1 = Reverse.vercodeWithTime()  # 得到图形验证码

        # 保存图形验证码，并用系统默认看图程序打开
        VERCODE_FILE.write_bytes(res1.content)
        threading.Thread(
            target=webbrowser.open,
            args=(VERCODE_FILE.resolve().as_uri(),),
            daemon=True,
        ).start()

        vercode = input("Input Vercode : ")

        Reverse.checkUserIdenty(vercode)

        # 添加secret Cookie
        secret = Reverse.generate_secret()
        Reverse.session.cookies.set(
            "secret", secret, domain="one.hfut.edu.cn", path="/"
        )

        # 验证登录
        Reverse.authorize()
        Reverse.login(vercode)
        res = Reverse.authorize()

        # 解析 URL，提取出code，之后获取token需要
        parsed = urlparse(res.url)
        params = parse_qs(parsed.query)
        code = params.get("code", [None])[0]

        logger.info("code : %s", code)

        # 将 code 存到 Reverse 类中
        Reverse.code = code

        # 获取token
        res2 = Reverse.getToken(code)
        token = res2.json()["data"]["access_token"]

        logger.info("token成功获取！ : %s", token)

        # 将 token 存到 Reverse 类中
        Reverse.token = token

        # 把token 存入cookie
        Reverse.session.cookies.set("token", token, domain="one.hfut.edu.cn", path="/")

        # print("当前Cookie:", Reverse.session.cookies.get_dict())
        # 应该有：SESSION JSESSIONID LOGINI_FAVOR TGC secret token

        Reverse.studentHome()
        Reverse.studentLogin()

        ok = Reverse.checkToken(token, code)

        # 登录成功后保存会话信息，供下次启动复用
        if ok:
            Reverse.save_session()

        return ok

    @staticmethod
    def login_cli() -> None:
        """执行一次登录流程并提示结果"""
        try:
            ok = UserCLI.init()
            if ok:
                logger.info("登录成功！")
            else:
                logger.warning("登录失败，请检查学号、密码或验证码。")
        except Exception as e:
            logger.error("登录过程发生错误：%s", e)
            logger.warning("请稍后重试，或检查网络 / 账号配置。")

    @staticmethod
    def query_hall_simple() -> None:
        """查询大厅用户基本信息"""
        try:
            if not Reverse.token or not Reverse.code:
                raise Exception("当前未登录或登录状态已丢失。")

            res = Reverse.selectUserSimplifyInfoForHall(Reverse.token, Reverse.code)
            logger.info("大厅基本信息：\n%s", log.format_json(res.json()))
        except Exception as e:
            logger.error("查询大厅信息失败：%s", e)
            logger.warning("可能是未登录或登录已失效，请先选择菜单 1 重新登录。")

    @staticmethod
    def query_hall_user_info() -> None:
        """查询大厅稍敏感的学生信息"""
        try:
            if not Reverse.token:
                raise Exception("当前未登录或登录状态已丢失。")

            res = Reverse.selectUserInfoForHall(token=Reverse.token)
            data = res.json()
            # 头像使用base64存储，无法直接输出
            data.get("data", {}).pop("avatorUrl", None)
            logger.info("大厅学生信息：\n%s", log.format_json(data))
        except Exception as e:
            logger.error("查询学生信息失败：%s", e)
            logger.warning("可能是未登录或登录已失效，请先选择菜单 1 重新登录。")

    @staticmethod
    def query_exam_arrange_info() -> None:
        try:
            if not Reverse.token:
                raise Exception("当前未登录或登录状态已丢失。")

            res = Reverse.examrrangeInfo()  # 返回html
            soup = BeautifulSoup(res.text, "html.parser")
            table = soup.find("table", id="exams")
            if not table:
                logger.warning("未找到考试表格（id='exams'），请检查页面结构或登录状态。")
                return

            rows = []
            tbody = table.find("tbody")
            for tr in tbody.find_all("tr"):
                tds = tr.find_all("td")
                if len(tds) < 2:
                    continue
                course = tds[0].get_text(strip=True)
                time_str = tds[1].get_text(strip=True)
                rows.append([course, time_str])

            # 用 tabulate 以表格形式输出，自动处理中英文宽度
            logger.info(
                "考试安排：\n%s",
                tabulate(
                    rows,
                    headers=["课程名称", "日期时间"],
                    tablefmt="grid",
                    showindex=True,
                ),
            )

        except Exception as e:
            logger.error("查询考试安排信息失败：%s", e)
            logger.warning("可能是未登录或登录已失效，请先选择菜单 1 重新登录。")

    @staticmethod
    def run() -> None:
        """简单交互命令行菜单"""
        while True:
            # 菜单整体作为一条日志输出，避免每行都带时间戳前缀
            logger.info(
                "\n===== HFUT Reverse CLI =====\n"
                "1. 登录 / 重新登录\n"
                "2. 查询大厅基本信息\n"
                "3. 查询大厅学生信息\n"
                "4. 查询考试安排信息\n"
                "q. 退出"
            )

            choice = input("请输入操作编号：").strip().lower()

            if choice == "1":
                UserCLI.login_cli()
            elif choice == "2":
                UserCLI.query_hall_simple()
            elif choice == "3":
                UserCLI.query_hall_user_info()
            elif choice == "4":
                UserCLI.query_exam_arrange_info()
            elif choice in ("q", "quit", "exit"):
                logger.info("已退出程序。")
                break
            else:
                logger.warning("无效选项，请重新输入。")


if __name__ == "__main__":
    # 启动交互式 CLI
    UserCLI.run()
