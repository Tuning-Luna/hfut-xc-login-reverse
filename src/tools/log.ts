function getCallerInfo() {
  const obj: { stack?: string } = {}
  Error.captureStackTrace(obj, getCallerInfo)
  const stack = obj.stack?.split("\n") ?? []

  // stack[0] 是 Error
  // stack[1] 是当前函数
  // stack[2] 才是调用 log 的文件位置
  const callerLine = stack[2] || stack[1] || ""
  const match = callerLine.match(/\((.*):(\d+):(\d+)\)/)

  if (match) {
    return {
      file: match[1],
      line: match[2],
      column: match[3],
    }
  }
  return {}
}

export function log(...args: any[]) {
  const caller = getCallerInfo()
  const prefix = caller.file ? `[${caller.file}:${caller.line}]` : ""
  console.log(prefix, ...args)
}

export function error(...args: any[]) {
  const caller = getCallerInfo()
  const prefix = caller.file ? `[${caller.file}:${caller.line}]` : ""
  console.error(prefix, ...args)
}

export function dir(...args: any[]) {
  const caller = getCallerInfo()
  const prefix = caller.file ? `[${caller.file}:${caller.line}]` : ""
  console.dir(prefix, ...args)
}
