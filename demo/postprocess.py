#!/usr/bin/env python3
"""Take demo-raw.mp4 and produce two GIF variants:
  demo.gif       — cool fast-forward effect (chromatic aberration + badge)
  demo-clean.gif — minimal: just speedx, no overlays

The FF window [FF_START, FF_END] seconds is compressed 6×.
"""
from __future__ import annotations
import argparse, subprocess, sys, shutil
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont
from moviepy import VideoFileClip, concatenate_videoclips, CompositeVideoClip, ImageClip, ColorClip
from moviepy.video.fx import MultiplySpeed

HERE = Path(__file__).parent
RAW = HERE / "demo-raw.mp4"

# from the recorded tape: scan command Enter pressed ~9s (after full command
# is typed), vhs sleeps 90s covering the ~60s scan + buffer, so the next
# interactive moment (dry-run typing) starts ~99s. compress this entire
# "scanning in progress" window — user doesn't need to watch a blinking cursor.
FF_START = 9.5
FF_END = 99.0
FF_SPEED = 20.0


def chromatic_aberration(clip, amount=2):
    """Subtle RGB channel shift during the fast-forward window for a 'glitch' feel."""
    def fx(get_frame, t):
        frame = get_frame(t).astype(np.int16)
        h, w = frame.shape[:2]
        out = frame.copy()
        # shift red channel right, blue channel left
        out[:, amount:, 0] = frame[:, :w-amount, 0]
        out[:, :w-amount, 2] = frame[:, amount:, 2]
        return np.clip(out, 0, 255).astype(np.uint8)
    return clip.transform(fx)


def build_badge(w=280, h=90, label=None):
    if label is None:
        label = f"FAST {int(FF_SPEED)}x"
    """Build a rounded-corner badge PNG with the FF label."""
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([(4, 4), (w-4, h-4)], radius=14,
                            fill=(18, 18, 26, 220),
                            outline=(120, 220, 255, 255), width=3)
    # try a few fonts to find one with the chars we want
    for path, size in [
        ("/System/Library/Fonts/Menlo.ttc", 42),
        ("/System/Library/Fonts/Supplemental/Courier New Bold.ttf", 44),
        ("/System/Library/Fonts/Helvetica.ttc", 44),
    ]:
        try:
            font = ImageFont.truetype(path, size)
            break
        except Exception:
            continue
    else:
        font = ImageFont.load_default()
    tw, th = draw.textbbox((0, 0), label, font=font)[2:]
    # draw twin chevrons in cyan left of the label
    chev = ">>"
    cw = draw.textbbox((0, 0), chev + " ", font=font)[2]
    total = cw + tw
    x0 = (w - total) / 2
    y0 = (h - th) / 2 - 4
    draw.text((x0, y0), chev, fill=(120, 220, 255, 255), font=font)
    draw.text((x0 + cw, y0), label, fill=(220, 245, 255, 255), font=font)
    return np.array(img)


def make_fancy(raw: VideoFileClip):
    pre = raw.subclipped(0, FF_START)
    mid_raw = raw.subclipped(FF_START, FF_END)
    post = raw.subclipped(FF_END, raw.duration)

    mid_fast = mid_raw.with_effects([MultiplySpeed(factor=FF_SPEED)])
    mid_aberrated = chromatic_aberration(mid_fast, amount=2)

    badge_np = build_badge()
    badge_w = badge_np.shape[1]
    badge_x = mid_aberrated.size[0] - badge_w - 20
    badge_clip = (ImageClip(badge_np)
                  .with_duration(mid_aberrated.duration)
                  .with_position((badge_x, 18))
                  .with_opacity(0.95))
    # gentle fade in/out on the badge
    fade = min(0.3, mid_aberrated.duration / 4)
    if fade > 0.05:
        from moviepy.video.fx import FadeIn, FadeOut
        badge_clip = badge_clip.with_effects([FadeIn(fade), FadeOut(fade)])
    mid_with_badge = CompositeVideoClip([mid_aberrated, badge_clip],
                                         size=mid_aberrated.size)

    # 3-frame white flash at each boundary as a transition snap
    flash = ColorClip(size=raw.size, color=(255, 255, 255), duration=3 / raw.fps)

    return concatenate_videoclips([pre, flash, mid_with_badge, flash, post],
                                    method="compose")


def make_clean(raw: VideoFileClip):
    pre = raw.subclipped(0, FF_START)
    mid = raw.subclipped(FF_START, FF_END).with_effects([MultiplySpeed(factor=FF_SPEED)])
    post = raw.subclipped(FF_END, raw.duration)
    return concatenate_videoclips([pre, mid, post], method="compose")


def export_gif(mp4_path: Path, gif_path: Path, fps=15, width=900):
    palette = mp4_path.with_suffix(".palette.png")
    # two-pass: generate palette, then use it (sharper colors, smaller file)
    subprocess.run([
        "ffmpeg", "-y", "-i", str(mp4_path),
        "-vf", f"fps={fps},scale={width}:-1:flags=lanczos,palettegen",
        str(palette),
    ], check=True, capture_output=True)
    subprocess.run([
        "ffmpeg", "-y", "-i", str(mp4_path), "-i", str(palette),
        "-filter_complex",
        f"fps={fps},scale={width}:-1:flags=lanczos[x];[x][1:v]paletteuse",
        str(gif_path),
    ], check=True, capture_output=True)
    palette.unlink(missing_ok=True)

    if shutil.which("gifsicle"):
        optimized = gif_path.with_suffix(".opt.gif")
        subprocess.run(["gifsicle", "-O3", "--colors", "128",
                        str(gif_path), "-o", str(optimized)],
                       check=False, capture_output=True)
        if optimized.exists() and optimized.stat().st_size > 0:
            optimized.replace(gif_path)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--variant", choices=["fancy", "clean", "both"], default="both")
    args = p.parse_args()

    if not RAW.exists():
        print(f"missing: {RAW}", file=sys.stderr)
        sys.exit(1)

    raw = VideoFileClip(str(RAW))
    print(f"raw duration: {raw.duration:.2f}s, {raw.fps}fps, {raw.size}")

    if args.variant in ("fancy", "both"):
        print("building fancy variant...")
        fancy = make_fancy(raw)
        fancy_mp4 = HERE / "demo.mp4"
        fancy.write_videofile(str(fancy_mp4), codec="libx264", audio=False,
                               preset="fast", logger=None)
        print("  → demo.mp4")
        export_gif(fancy_mp4, HERE / "demo.gif")
        print(f"  → demo.gif ({(HERE / 'demo.gif').stat().st_size / 1e6:.2f} MB)")

    if args.variant in ("clean", "both"):
        print("building clean variant...")
        clean = make_clean(raw)
        clean_mp4 = HERE / "demo-clean.mp4"
        clean.write_videofile(str(clean_mp4), codec="libx264", audio=False,
                               preset="fast", logger=None)
        print("  → demo-clean.mp4")
        export_gif(clean_mp4, HERE / "demo-clean.gif")
        print(f"  → demo-clean.gif ({(HERE / 'demo-clean.gif').stat().st_size / 1e6:.2f} MB)")


if __name__ == "__main__":
    main()
