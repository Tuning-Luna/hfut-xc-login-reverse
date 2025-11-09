import { preLogin } from "./preLogin/preLogin"
import { log } from "./tools/log"
import { cookieStore } from "./tools/cookieManagerNoDep"
import { getVercode } from "./vercode/vercode"
import { checkInitParams } from "./checkInitParams/checkInitParams"
import { getVercodeWithTime } from "./vercode/vercodeWithTime"
import { saveFile } from "./tools/saveFile"
import { openImage } from "./tools/openImage"
import { inputFromCmd } from "./tools/inputFromCmd"
import { checkUserIdenty } from "./checkUserIdenty/checkUserIdenty"

async function main() {
  // 让用户输入StudentID和Password
  // const studentID = await inputFromCmd("请输入学号:")
  const studentID = Bun.env.STUDENT_ID
  log(studentID)
  // const password = await inputFromCmd("请输入密码:")
  const password = Bun.env.PASSWORD
  log(password)

  // 预加载
  await preLogin()
  // log("预加载完成，得到cookie如下：", cookieStore)

  // 第一次请求图形验证码，但是不会使用，应该是为了获得JSESSIONID字段
  const res1 = await getVercode()
  saveFile("vercode.png", new Uint8Array(res1.data))
  // log("第一次请求图形验证码完成，得到cookie如下：", cookieStore)

  // 检查初始化
  await checkInitParams()
  // log("调用检查初始化函数后，cookie如下：", cookieStore)

  // 第二次请求图形验证码，就是登陆的时候需要输入的
  const res2 = await getVercodeWithTime()
  const file = saveFile("vercodeWithTime.png", new Uint8Array(res2.data))
  await openImage(file) // 打开器打开验证码图片,让用户输入图形验证码

  // 可以使用tesseract解析图形验证码（已经配置好），但是效果一言难尽。还是选择手动输入
  const verCodeStr = await inputFromCmd("请输入图形验证码：")

  const res3 = await checkUserIdenty(studentID!, password!, verCodeStr)
  log(res3.data)
}

main()
  .then(() => {
    log("全部任务完成，进程退出")
    process.exit(0) // 成功退出
  })
  .catch((err) => {
    console.error("执行出错:", err)
    process.exit(1) // 错误退出
  })
