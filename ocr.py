import easyocr

# 只初始化一次
reader = easyocr.Reader(["en"], gpu=False)  # gpu=False 避免显卡问题

# 改成你的图片路径
img_path = "vercode.png"

results = reader.readtext(img_path)

print("识别出的所有文字：")
for bbox, text, prob in results:
    print(text)
