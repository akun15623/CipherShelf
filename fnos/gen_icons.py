#!/usr/bin/env python3
"""生成 ciphershelf 飞牛应用图标（锁形，蓝底）。

用法：在仓库根目录执行
    python3 fnos/gen_icons.py fnos/docker/ciphershelf
（需要 Pillow）
"""
import sys

from PIL import Image, ImageDraw


def make_icon(size: int) -> Image.Image:
    # 蓝→紫渐变背景 + 圆角裁切
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    for y in range(size):
        t = y / size
        r = int(41 + (74 - 41) * t)
        g = int(112 + (86 - 112) * t)
        b = int(255 + (223 - 255) * t)
        d.line([(0, y), (size, y)], fill=(r, g, b, 255))

    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, size - 1, size - 1], radius=int(size * 0.22), fill=255
    )
    img.putalpha(mask)

    d = ImageDraw.Draw(img)
    s = size / 256.0

    def S(v):
        return int(v * s)

    # 锁梁（上半圆弧，白色粗线）
    d.arc([S(88), S(52), S(168), S(132)], start=180, end=360, fill=(255, 255, 255, 255), width=S(22))
    # 锁体（白色圆角矩形）
    d.rounded_rectangle([S(72), S(122), S(184), S(224)], radius=S(18), fill=(255, 255, 255, 255))
    # 锁孔（蓝点）
    r = S(13)
    d.ellipse([S(128) - r, S(164) - r, S(128) + r, S(164) + r], fill=(41, 112, 255, 255))
    return img


def main() -> None:
    if len(sys.argv) != 2:
        print(f"用法：python3 {sys.argv[0]} <包目录>")
        sys.exit(1)
    dest = sys.argv[1].rstrip("/")

    for name, size in [
        ("ICON.PNG", 64),
        ("ICON_256.PNG", 256),
        ("app/ui/images/icon_64.png", 64),
        ("app/ui/images/icon_256.png", 256),
    ]:
        icon = make_icon(size)
        if icon.mode == "RGBA":
            icon = icon.convert("RGB")
        path = f"{dest}/{name}"
        icon.save(path, "PNG")
        print(f"生成 {name} ({size}x{size})")

    print("图标生成完成")


if __name__ == "__main__":
    main()
