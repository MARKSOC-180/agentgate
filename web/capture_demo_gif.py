#!/usr/bin/env python3
"""把 web/danger.html 录成 GIF，供 README / 社媒传播。

依赖（仅开发/发布时用，非运行时依赖）：
    pip install playwright pillow
    playwright install chromium

用法：
    python web/capture_demo_gif.py
    # -> assets/danger_demo.gif
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "web" / "danger.html"
OUT = ROOT / "assets" / "danger_demo.gif"


def capture() -> Path:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise SystemExit(
            "需要 playwright：pip install playwright && playwright install chromium"
        ) from e
    from PIL import Image

    url = HTML.as_uri() + "?autoplay=1&fast=1"
    frames: list[Image.Image] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1200, "height": 920})
        page.goto(url, wait_until="networkidle")
        # 动画约 5 步 × ~690ms + 收尾 ≈ 4s；多采几帧保证 GIF 流畅
        for _ in range(36):
            png = page.screenshot(type="png", full_page=False)
            frames.append(Image.open(io.BytesIO(png)).convert("P", palette=Image.ADAPTIVE))
            page.wait_for_timeout(180)
        browser.close()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    target_w = 720
    sized = []
    for fr in frames:
        h = int(fr.height * target_w / fr.width)
        sized.append(fr.resize((target_w, h), Image.Resampling.LANCZOS).convert("P", palette=Image.ADAPTIVE))

    sized[0].save(
        OUT,
        save_all=True,
        append_images=sized[1:],
        duration=180,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"wrote {OUT} ({len(sized)} frames, {OUT.stat().st_size // 1024} KiB)")
    return OUT


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    capture()
