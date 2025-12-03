import os
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from reverse import Reverse
from tabulate import tabulate


class UserCLI:

    # 初始化用户
    @staticmethod
    def init() -> bool:
        # 如果可以从本地文件恢复会话，就直接返回，不再走验证码登录流程
        if Reverse.load_session():
            return True

        Reverse.preLogin()
        Reverse.vercode()
        Reverse.checkInitParams()
        res1 = Reverse.vercodeWithTime()  # 得到图形验证码

        # 保存图形验证码
        filename = "vercode.png"
        with open(filename, "wb") as f:
            f.write(res1.content)
        os.startfile(filename)  # 打开验证码图片

        vercode = input("Input Vercode : ")

        Reverse.checkUserIdenty(vercode)

        # 添加secret Cookie
        secret = Reverse.generate_secret()
        Reverse.session.cookies.set(
            "secret", secret, domain="one.hfut.edu.cn", path="/"
        )

        # # 验证登录
        Reverse.authorize()
        Reverse.login(vercode)
        res = Reverse.authorize()

        # 解析 URL，提取出code，之后获取token需要
        parsed = urlparse(res.url)
        params = parse_qs(parsed.query)
        code = params.get("code", [None])[0]

        print("code : ", code)

        # 将 code 存到 Reverse 类中
        Reverse.code = code

        # 获取token
        res2 = Reverse.getToken(code)
        token = res2.json()["data"]["access_token"]

        print("token成功获取！ : ", token)

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
                print("登录成功！")
            else:
                print("登录失败，请检查学号、密码或验证码。")
        except Exception as e:
            print("登录过程发生错误：", e)
            print("请稍后重试，或检查网络 / 账号配置。")

    @staticmethod
    def query_hall_simple() -> None:
        """查询大厅用户基本信息"""
        try:
            if not Reverse.token or not Reverse.code:
                raise Exception("当前未登录或登录状态已丢失。")

            res = Reverse.selectUserSimplifyInfoForHall(Reverse.token, Reverse.code)
            print("大厅基本信息：")
            print(res.json())
        except Exception as e:
            print("查询大厅信息失败：", e)
            print("可能是未登录或登录已失效，请先选择菜单 1 重新登录。")

    @staticmethod
    def query_hall_user_info() -> None:
        """查询大厅稍敏感的学生信息"""
        try:
            if not Reverse.token:
                raise Exception("当前未登录或登录状态已丢失。")

            res = Reverse.selectUserInfoForHall(token=Reverse.token)
            print("大厅学生信息：")
            print(res.json())
        except Exception as e:
            print("查询学生信息失败：", e)
            print("可能是未登录或登录已失效，请先选择菜单 1 重新登录。")

    @staticmethod
    def query_exam_arrange_info() -> None:
        try:
            if not Reverse.token:
                raise Exception("当前未登录或登录状态已丢失。")

            res = Reverse.examrrangeInfo()  # 返回html
            soup = BeautifulSoup(res.text, "html.parser")
            table = soup.find("table", id="exams")
            if not table:
                print("未找到考试表格（id='exams'），请检查页面结构或登录状态。")
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

            # 用 tabulate 以表格形式打印，自动处理中英文宽度
            print(
                tabulate(
                    rows,
                    headers=["课程名称", "日期时间"],
                    tablefmt="grid",
                    showindex=True,
                )
            )

        except Exception as e:
            print("查询考试安排信息失败：", e)
            print("可能是未登录或登录已失效，请先选择菜单 1 重新登录。")

    @staticmethod
    def run() -> None:
        """简单交互命令行菜单"""
        while True:
            print("\n===== HFUT Reverse CLI =====")
            print("1. 登录 / 重新登录")
            print("2. 查询大厅基本信息")
            print("3. 查询大厅学生信息")
            print("4. 查询考试安排信息")
            print("q. 退出")

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
                print("已退出程序。")
                break
            else:
                print("无效选项，请重新输入。")


if __name__ == "__main__":
    # 启动交互式 CLI
    UserCLI.run()
