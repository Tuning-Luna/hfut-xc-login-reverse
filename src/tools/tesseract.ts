import { createWorker, PSM } from "tesseract.js"
import { log } from "./log"
import sharp from "sharp" // 新增：用于预处理

export async function parseVercode(
  image: Buffer | Uint8Array | ArrayBuffer
): Promise<string> {
  // 1. 转成 Buffer
  let buf = Buffer.isBuffer(image)
    ? image
    : Buffer.from(image instanceof ArrayBuffer ? new Uint8Array(image) : image)

  // 2. 预处理图像（新增：用 sharp 优化验证码）
  try {
    buf = await sharp(buf)
      .resize({ width: 200 }) // 固定宽度，200px 是经验值
      .greyscale()
      .threshold(160) // 阈值偏高，可以测试 140~180
      .median(1) // 代替 blur，更适合去噪
      .toBuffer()

    log("预处理完成：灰度 + 模糊 + 二值化 + 锐化 + 缩放")
  } catch (err) {
    log("预处理失败:", err instanceof Error ? err.message : String(err))
    // 继续用原 buf，避免崩溃
  }

  // 3. 创建 worker，用本地 langPath 绕过下载
  let worker
  try {
    worker = await createWorker("eng", 1, {
      // 1 = LSTM 引擎，更准
      logger: (m) =>
        log(
          `Tesseract ${m.status}: ${
            m.progress ? (m.progress * 100).toFixed(0) + "%" : "N/A"
          }`
        ),
      langPath: "./tessdata",
      cachePath: "./tesscache",
      gzip: false,
    })
  } catch (err) {
    log("创建worker失败:", err instanceof Error ? err.message : String(err))
    throw err
  }

  // 4. 设置参数（优化：验证码专用）
  await worker.setParameters({
    tessedit_char_whitelist: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    tessedit_pageseg_mode: PSM.SINGLE_CHAR, // ✅ 单字符模式最适合验证码
    classify_bln_numeric_mode: "1", // 偏向数字/验证码风格
    ocr_engine_mode: "1", // OEM_LSTM_ONLY
    load_system_dawg: "0",
    load_freq_dawg: "0",
    tessedit_enable_dict_correction: "0",
    user_defined_dpi: "300",
  })

  // 5. 识别，加 30 秒超时防卡
  let result
  try {
    result = await Promise.race([
      worker.recognize(buf, { rotateAuto: true }), // 新增：自动旋转（如果图像歪）
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("OCR 超时（30s），可能是图像问题")),
          30000
        )
      ),
    ])
  } catch (err: unknown) {
    log("识别失败:", err instanceof Error ? err.message : String(err))
    await worker.terminate()
    throw err
  }

  const {
    data: { text },
  } = result as { data: { text: string; confidence: number } }
  const code = text
    .replace(/[^A-Za-z0-9]/g, "")
    .trim()
    .toUpperCase() // 改：大写化，常见验证码不分大小

  log("OCR 结果:", code)
  await worker.terminate()
  return code
}
