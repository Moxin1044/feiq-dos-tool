# -*- coding: utf-8 -*-
"""启动 GUI 工具并截图（用 PrintWindow 抓窗口）"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

_HERE = __file__.rsplit("\\", 1)[0]
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_HERE, "bin", "feiq_dos.exe")
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(_HERE, "gui_preview.png")

subprocess.Popen([EXE], cwd=_HERE)
time.sleep(3)

# 找窗口
hwnd = 0
titles = []


def cb(h, l):
    if user32.IsWindowVisible(h):
        n = user32.GetWindowTextLengthW(h)
        if n:
            b = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(h, b, n + 1)
            titles.append((h, b.value))
    return True


WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
user32.EnumWindows(WNDENUMPROC(cb), 0)
for h, t in titles:
    if "飞秋" in t or "DoSTool" in t:
        hwnd = h
        print("找到窗口:", t, hex(h))
        break
if not hwnd:
    print("未找到窗口；可见窗口列表：")
    for h, t in titles[:25]:
        print("   ", hex(h), t)
    sys.exit(1)

# 置前
user32.SetForegroundWindow(hwnd)
time.sleep(0.6)

rc = wt.RECT()
user32.GetWindowRect(hwnd, ctypes.byref(rc))
w = rc.right - rc.left
h = rc.bottom - rc.top
print("窗口尺寸: %dx%d" % (w, h))

hdc = user32.GetWindowDC(hwnd)
mdc = gdi32.CreateCompatibleDC(hdc)
bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
gdi32.SelectObject(mdc, bmp)
user32.PrintWindow(hwnd, mdc, 0)
time.sleep(0.4)

# 取出位图 -> PNG
from PIL import Image
class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", ctypes.c_long), ("biHeight", ctypes.c_long),
                ("biPlanes", wt.WORD), ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wt.DWORD),
                ("biClrImportant", wt.DWORD)]

bi = BITMAPINFOHEADER()
bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
bi.biWidth = w
bi.biHeight = -h
bi.biPlanes = 1
bi.biBitCount = 32
bi.biCompression = 0
buf = ctypes.create_string_buffer(w * h * 4)
gdi32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), 0)
img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1)
img.convert("RGB").save(OUT)
print("已保存:", OUT)

gdi32.DeleteObject(bmp)
gdi32.DeleteDC(mdc)
user32.ReleaseDC(hwnd, hdc)
