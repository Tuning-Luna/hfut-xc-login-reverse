# 先 pip 安装依赖（只需执行一次）
# pip install paddlepaddle paddleocr opencv-python

from paddleocr import PaddleOCR
import cv2
from typing import Any, List, Optional, Sequence, Tuple

__all__ = ["initial", "识别"]


def initial(lang: str = "en", **kwargs) -> PaddleOCR:
    """
    初始化 OCR 引擎，只需调用一次即可复用。

    参数:
        lang: OCR 支持的语言，默认英文数字混排效果最好。
        kwargs: 要透传给 PaddleOCR 的其他配置。

    返回:
        PaddleOCR 实例，可在多个识别请求中重复使用。
    """
    kwargs.setdefault("use_textline_orientation", True)
    return PaddleOCR(lang=lang, **kwargs)


def _load_image(image_path: str):
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"无法读取图片：{image_path}")

    if len(img.shape) == 3 and img.shape[2] == 4:
        img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)

    return img


def _is_legacy_line(item: Any) -> bool:
    return (
        isinstance(item, (list, tuple))
        and len(item) >= 2
        and isinstance(item[1], (list, tuple))
        and len(item[1]) >= 1
        and isinstance(item[1][0], str)
    )


def _collect_texts(obj: Any, bucket: List[Tuple[str, Optional[float]]]) -> None:
    if obj is None:
        return

    if _is_legacy_line(obj):
        text = obj[1][0]
        confidence = obj[1][1] if len(obj[1]) > 1 else None
        bucket.append((text, confidence))
        return

    if isinstance(obj, dict):
        if "rec_texts" in obj:
            scores = obj.get("rec_scores", [])
            for idx, text in enumerate(obj["rec_texts"]):
                score = scores[idx] if idx < len(scores) else None
                bucket.append((text, score))
            return

        if any(key in obj for key in ("text", "transcription")):
            text = obj.get("text") or obj.get("transcription")
            confidence = obj.get("confidence") or obj.get("score")
            if text:
                bucket.append((text, confidence))
            return

        for value in obj.values():
            _collect_texts(value, bucket)
        return

    if isinstance(obj, (list, tuple)):
        for item in obj:
            _collect_texts(item, bucket)
        return

    if isinstance(obj, str):
        bucket.append((obj, None))


def extract_texts(raw_result: Any) -> List[Tuple[str, Optional[float]]]:
    texts: List[Tuple[str, Optional[float]]] = []
    _collect_texts(raw_result, texts)
    return texts


def ocr_text(
    ocr: PaddleOCR,
    image_path: str,
    join_with: str = "\n",
) -> str:
    """
    执行 OCR 识别，返回拼接好的纯文字结果。

    参数:
        ocr: 通过 initial() 得到的 OCR 引擎。
        image_path: 待识别图片路径，支持 jpg/png 等格式。
        join_with: 多行文本的拼接符，默认为换行。

    返回:
        识别出的文字（用 join_with 拼接），若没有结果返回空字符串。
    """
    img = _load_image(image_path)

    try:
        raw_result = ocr.predict(img)
    except AttributeError:
        raw_result = ocr.ocr(img)

    texts_with_scores = extract_texts(raw_result)
    if not texts_with_scores:
        return ""

    formatted = []
    for text, confidence in texts_with_scores:
        if not text:
            continue
        if confidence is None:
            formatted.append(text)
        else:
            formatted.append(f"{text},{confidence:.2f}")

    return join_with.join(formatted)


import os

if __name__ == "__main__":
    ocr_engine = initial()  # 初始化 OCR 引擎

    folder = "./vercode"
    support_ext = {".jpg", ".png", ".jpeg", ".bmp"}

    # 遍历整个目录
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)

        # 跳过非文件
        if not os.path.isfile(file_path):
            continue

        # 只识别指定格式
        ext = os.path.splitext(filename)[1].lower()
        if ext not in support_ext:
            continue

        print("=" * 40)
        print("当前识别文件:", filename)

        # OCR识别
        result = ocr_text(ocr_engine, file_path)

        if not result:
            print("❌ 没识别到有效文本\n")
            continue

        print("原始返回:", result)

        # 如果包含“文字,置信度”
        if isinstance(result, str) and "," in result:
            text, score = result.split(",", 1)
            print("文字:", text)
            print("置信度:", score)
        else:
            print("文字:", result)

        print()  # 空行
