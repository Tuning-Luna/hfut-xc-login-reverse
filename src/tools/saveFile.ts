import { mkdirSync, writeFileSync } from "fs"
import { dirname, resolve } from "path"
import { log } from "./log"

// 获取当前调用者文件目录
function getCallerDir() {
  const err = new Error()
  const stack = err.stack?.split("\n") ?? []

  // stack[0] 是 Error
  // stack[1] 是本函数
  // stack[2] 是 saveFile
  // stack[3] 才是调用者
  const callerLine = stack[3]

  // 从 `(.../path/file.ts:line:col)` 中提取路径
  const match = callerLine!.match(/\((.*):\d+:\d+\)/)
  const callerFile = match?.[1]

  // Bun/Node 路径处理
  return callerFile ? dirname(callerFile) : process.cwd()
}

export function saveFile(filename: string, data: string | Uint8Array) {
  const callerDir = getCallerDir()
  const resultDir = resolve(callerDir, "./result")

  mkdirSync(resultDir, { recursive: true })

  const filePath = resolve(resultDir, filename)

  writeFileSync(filePath, data)

  log(`文件已保存: ${filePath}`)

  return filePath // ✅ 返回绝对路径
}
