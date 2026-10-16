# 飞秋远程拒绝服务工具

针对飞秋 3.0.0.2 的远程 DoS 工具，C + Win32 单文件，编译后 12 KB。
零 CRT 依赖，Windows XP SP3 起可运行。

## 用法

界面：双击 exe，填目标 IP 和源 IP，选模式，点开始。

命令行：

```
feiq_dos.exe <目标IP> [源IP] [single|loop|timed] [--go]
```

加了 `--go` 就直接开打，不加就只预填界面。

三种模式：

- **单次** — 打一轮就停
- **循环压制** — 打一轮，然后一直探测，目标一恢复就再打
- **定时** — 跟循环压制一样，到时间自己停

循环间隔（毫秒）和定时时长（分钟）在界面上填。

## 漏洞

飞秋处理 UDP 2425 上的图片/资源分片时是这么写的：

```c
hMem = GlobalAlloc(GMEM_ZEROINIT, dwBytes);   // dwBytes 来自报文
base = GlobalLock(hMem);
memcpy(base + offset, src, Size);             // offset / Size 也来自报文
```

分配大小、目的偏移、拷贝长度三项全从网络来，一个都没校验。只要让 `offset + Size`
超过 `dwBytes` 就是堆越界写，堆结构坏了以后进程以 `0xC0000374`
（STATUS_HEAP_CORRUPTION）退出。

工具默认发这四个包：

```
越界-16     分配 16      偏移 0       附加 8000   共 8113 字节
越界-1024   分配 1024    偏移 0       附加 8000   共 8115 字节
越界-64     分配 64      偏移 0       附加 8000   共 8113 字节
负偏移      分配 64      偏移 -8016   附加 8000   共 8117 字节
```

一轮约 32 KB。远程打下去 2.9 秒掉线，而且飞秋不会自己重启，就一直停在那。

单发一个包也能打掉，但不稳。远程只能靠 UDP 探测判断目标死没死，而探测报文本身会动到
目标的堆布局，实测单包成功率只有 40~60%。所以默认是连发四个，5/5 成功。

## 为什么能在 XP 上跑

XP 上没有 UCRT / vcruntime，现在 MSVC 默认编出来的东西在 XP 上直接起不来。绕法：

- `/NODEFAULTLIB` + 自己写入口 `WinMainCRTStartup`，完全不链 CRT
- `memset` / `memcpy` 在源码里自己实现，配上 `#pragma function` 关掉编译器的内置处理，
  否则 MSVC 不让重定义
- 一行浮点都没有（时间显示用整数除法），不然会拉进 `_ftlused` / `_ftol`
- `/GS-` 关掉栈检查，避免引入 `__security_cookie`
- `/SUBSYSTEM:WINDOWS,5.01`
- 只用 XP 就有的 API，不碰 Vista 之后的东西

界面是系统标准控件（STATIC / EDIT / BUTTON），字体用 `SPI_GETNONCLIENTMETRICS` 取，
消息循环走一遍 `IsDialogMessageW` 拿到正常的 Tab 和回车响应。所以外观就是系统的默认样子
—— XP 上是 Luna，Win10/11 上是当前的控件样式。

导入表只剩四个系统 DLL，没有 CRT：

```
KERNEL32.dll  USER32.dll  GDI32.dll  WS2_32.dll
```

## 编译

```
build_msvc.bat
```

需要 VS 的 x86 工具链，脚本自己去找 `vcvars32.bat`。

## 跑过的验证

```
本地靶机     4 向量连发，5/5 成功
远程靶机     2.9 秒掉线
同实例对照   1 个包 → 还活着；4 个包 → 掉线（只有包数不一样）
崩溃类型     0xC0000374，目标机事件日志里能查到
主机层       目标机 ARP 一直是 Reachable，是进程死了不是断网
循环压制     目标恢复后 8 秒内又被打掉
```

## 文件

```
src/feiq_dos.c      源码，单文件
build_msvc.bat      构建脚本
bin/feiq_dos.exe    产物
gui_preview.png     界面
gui_success.png     实际跑起来的截图
```

## 修复

给飞秋改的话，`memcpy` 之前把两个数卡住就行：

```c
if (offset >= 0 && (unsigned)offset + Size <= dwBytes) { ... }
```

`offset` 是 `_wtoi` 出来的有符号数，比较时必须按无符号，不然负偏移直接就绕过去了。
另外 `dwBytes` 也该给个上限。分片序号和 bitmap 索引也顺手对一下。

---

只在自己的环境或已授权的范围里用。
