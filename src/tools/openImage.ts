import { exec } from "child_process"

export function openImage(filePath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const platform = process.platform

    let cmd = ""
    if (platform === "win32") cmd = `start "" "${filePath}"`
    else if (platform === "darwin") cmd = `open "${filePath}"`
    else cmd = `xdg-open "${filePath}"`

    exec(cmd, (err) => {
      if (err) reject(err)
      else resolve()
    })
  })
}
