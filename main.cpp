#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define _WIN32_WINNT 0x0601   // Windows 7+：启用 TOKEN_ELEVATION 等定义

#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <mmsystem.h>
#include <sddl.h>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------- 题目数据
static const wchar_t* kQuestion = L"你是小南梁吗？";

static const wchar_t* kOptionText[4] = {
    L"是的喵！",
    L"不是啊！",
    L"是小药娘啦！",
    L"想当小南梁！",
};

// 当前显示顺序：g_order[显示位置] = 原始选项下标
static std::vector<int> g_order = { 0, 1, 2, 3 };
static std::mutex       g_orderMtx;

static std::atomic<bool> g_running{ true };   // 洗牌线程是否继续运行
static std::atomic<bool> g_frozen{ false };   // 用户是否已经选择
static std::thread       g_worker;
static HWND              g_hwnd = nullptr;

// 运行身份：标准 / 管理员 / SYSTEM / TrustedInstaller
enum class RunLevel { Standard, Admin, System, TrustedInstaller };

// -1 表示不强制（标准模式）；否则为点击后强制落到的选项下标。
// 该值只影响点击结果，不参与任何绘制，因此各模式外观完全一致。
static int g_forcedOption = -1;

static int g_chosenSlot = -1;   // 被点击的显示位置
static int g_chosenOption = -1;   // 该位置对应的原始选项下标

// ---------------------------------------------------------------- DPI
// 以下数值均以 96 DPI 为基准，运行时按实际 DPI 等比缩放。
static const int kPad = 26;   // 左右内边距
static const int kQuestionH = 48;   // 题干高度
static const int kGapAfterQ = 26;   // 题干与选项间距
static const int kOptionH = 66;   // 选项高度
static const int kOptionGap = 22;   // 选项间距
static const int kRadius = 14;   // 圆角半径
static const int kBaseClientW = 440;
static const int kBaseClientH = 560;

static int S(int base, UINT dpi) { return MulDiv(base, (int)dpi, 96); }

// 开启高 DPI 感知：优先 Per-Monitor V2，逐级回退。
// 全部动态解析，避免对较新系统 DLL 的导入依赖。
static void EnableHighDpiAwareness()
{
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        typedef BOOL(WINAPI* PFN_SetProcessDpiAwarenessContext)(void*);
        auto setCtx = (PFN_SetProcessDpiAwarenessContext)
            GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4
        if (setCtx && setCtx((void*)-4)) return;
    }

    HMODULE shcore = LoadLibraryW(L"shcore.dll");
    if (shcore) {
        typedef HRESULT(WINAPI* PFN_SetProcessDpiAwareness)(int);
        auto setAwareness = (PFN_SetProcessDpiAwareness)
            GetProcAddress(shcore, "SetProcessDpiAwareness");
        // PROCESS_PER_MONITOR_DPI_AWARE == 2
        if (setAwareness && setAwareness(2) == S_OK) { FreeLibrary(shcore); return; }
        FreeLibrary(shcore);
    }

    SetProcessDPIAware();   // 系统 DPI 感知（Vista+ 兜底）
}

static UINT GetWindowDpi(HWND hwnd)
{
    static HMODULE user32 = GetModuleHandleW(L"user32.dll");
    typedef UINT(WINAPI* PFN_GetDpiForWindow)(HWND);
    static auto getDpiForWindow = user32
        ? (PFN_GetDpiForWindow)GetProcAddress(user32, "GetDpiForWindow")
        : nullptr;

    if (getDpiForWindow) return getDpiForWindow(hwnd);

    HDC dc = GetDC(hwnd);
    UINT dpi = dc ? (UINT)GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc) ReleaseDC(hwnd, dc);
    return dpi ? dpi : 96;
}

static UINT GetPrimaryDpi()
{
    HDC dc = GetDC(nullptr);
    UINT dpi = dc ? (UINT)GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc) ReleaseDC(nullptr, dc);
    return dpi ? dpi : 96;
}

// ---------------------------------------------------------------- 运行身份检测
// 通过令牌的 TokenElevation 判断当前进程是否已提升为管理员。
static bool IsElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION elevation = {};
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(
        token, TokenElevation, &elevation, sizeof(elevation), &returned);
    CloseHandle(token);

    return ok && elevation.TokenIsElevated != 0;
}

// 取当前进程令牌的用户 SID 字符串，例如 "S-1-5-18"。
static std::wstring GetTokenUserSid()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return std::wstring();

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0) {
        CloseHandle(token);
        return std::wstring();
    }

    std::vector<BYTE> buffer(size);
    std::wstring sidString;
    if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        const TOKEN_USER* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
        LPWSTR text = nullptr;
        if (ConvertSidToStringSidW(user->User.Sid, &text)) {
            sidString = text;
            LocalFree(text);
        }
    }
    CloseHandle(token);
    return sidString;
}

// 判断令牌的组列表里是否含有指定 SID。
// 服务 SID（S-1-5-80-*）是以"组"的身份加入令牌的，必须单独查这里。
static bool TokenHasGroupSid(const wchar_t* targetSid)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    DWORD size = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    if (size == 0) {
        CloseHandle(token);
        return false;
    }

    std::vector<BYTE> buffer(size);
    bool found = false;
    if (GetTokenInformation(token, TokenGroups, buffer.data(), size, &size)) {
        const TOKEN_GROUPS* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
        for (DWORD i = 0; i < groups->GroupCount; ++i) {
            LPWSTR text = nullptr;
            if (ConvertSidToStringSidW(groups->Groups[i].Sid, &text)) {
                const bool match = (wcscmp(text, targetSid) == 0);
                LocalFree(text);
                if (match) { found = true; break; }
            }
        }
    }
    CloseHandle(token);
    return found;
}

// 判定优先级：TrustedInstaller > SYSTEM > 管理员 > 标准。
// 必须先比对 SID 再判断提权，因为 SYSTEM 令牌同样满足 TokenElevation。
static RunLevel DetectRunLevel()
{
    // TrustedInstaller 服务的账户 SID（NT SERVICE\TrustedInstaller）
    static const wchar_t* kTrustedInstallerSid =
        L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    const std::wstring userSid = GetTokenUserSid();

    // TrustedInstaller 可能作为令牌用户出现，也可能只作为"已知组"出现在组列表里
    // （此时令牌用户是 SYSTEM）。两种情形都要识别，且必须排在 SYSTEM 判断之前。
    if (userSid == kTrustedInstallerSid || TokenHasGroupSid(kTrustedInstallerSid))
        return RunLevel::TrustedInstaller;

    if (userSid == L"S-1-5-18")          // NT AUTHORITY\SYSTEM
        return RunLevel::System;

    if (IsElevated()) return RunLevel::Admin;
    return RunLevel::Standard;
}

// ---------------------------------------------------------------- 布局
static void GetLayout(HWND hwnd, UINT dpi, RECT optRects[4], RECT& qRect, RECT& resultRect)
{
    RECT rc;
    GetClientRect(hwnd, &rc);

    const int pad = S(kPad, dpi);
    const int qh = S(kQuestionH, dpi);
    const int gap = S(kGapAfterQ, dpi);
    const int oh = S(kOptionH, dpi);
    const int og = S(kOptionGap, dpi);
    const int right = rc.right - pad;

    qRect = { pad, pad, right, pad + qh };

    int y = pad + qh + gap;
    for (int i = 0; i < 4; ++i) {
        optRects[i] = { pad, y, right, y + oh };
        y += oh + og;
    }
    resultRect = { pad, y, right, rc.bottom - pad };
}

// ---------------------------------------------------------------- 字体
static HFONT CreateAppFont(int pixelSize, bool bold)
{
    return CreateFontW(
        -pixelSize, 0, 0, 0,
        bold ? FW_BOLD : FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
        L"Microsoft YaHei UI");
}

// ---------------------------------------------------------------- 洗牌线程
// 定格瞬间用来重排选项的随机源
static std::mt19937& ClickRng()
{
    static std::mt19937 rng(std::random_device{}());
    return rng;
}

// 每 1ms 重新随机排列一次选项顺序，并请求重绘。
static void ShuffleLoop()
{
    std::mt19937 rng(std::random_device{}());
    while (g_running.load(std::memory_order_relaxed)) {
        {
            std::lock_guard<std::mutex> lock(g_orderMtx);
            std::shuffle(g_order.begin(), g_order.end(), rng);
        }
        if (g_hwnd) InvalidateRect(g_hwnd, nullptr, FALSE);
        Sleep(1);
    }
}

// ---------------------------------------------------------------- 绘制
static void PaintWindow(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc;
    GetClientRect(hwnd, &rc);
    const int W = rc.right;
    const int H = rc.bottom;
    const UINT dpi = GetWindowDpi(hwnd);

    // 双缓冲，避免闪烁
    HDC     memDC = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, bmp);

    // 深色渐变背景
    TRIVERTEX vert[2] = {
        { 0, 0, 0x3c00, 0x3c00, 0x4000, 0xff00 },
        { W, H, 0x1c00, 0x1c00, 0x2000, 0xff00 },
    };
    GRADIENT_RECT gr = { 0, 1 };
    GradientFill(memDC, vert, 2, &gr, 1, GRADIENT_FILL_RECT_V);

    SetBkMode(memDC, TRANSPARENT);

    RECT optRects[4], qRect, resultRect;
    GetLayout(hwnd, dpi, optRects, qRect, resultRect);

    HFONT hQuestion = CreateAppFont(S(30, dpi), true);
    HFONT hOption = CreateAppFont(S(26, dpi), false);
    HFONT hHint = CreateAppFont(S(18, dpi), false);
    HFONT hResult = CreateAppFont(S(23, dpi), true);
    HFONT hOldFont = (HFONT)SelectObject(memDC, hQuestion);

    // 题干
    SetTextColor(memDC, RGB(246, 246, 246));
    DrawTextW(memDC, kQuestion, -1, &qRect,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    // 读取当前显示顺序
    std::vector<int> order;
    {
        std::lock_guard<std::mutex> lock(g_orderMtx);
        order = g_order;
    }

    // 选项
    SelectObject(memDC, hOption);
    for (int i = 0; i < 4; ++i) {
        const RECT r = optRects[i];
        const bool chosen = g_frozen.load() && (g_chosenSlot == i);

        const COLORREF fill = chosen ? RGB(0x3d, 0x7b, 0xea) : RGB(0x6c, 0x6c, 0x72);
        const COLORREF border = chosen ? RGB(0x9c, 0xc4, 0xff) : RGB(0x85, 0x85, 0x8c);

        HBRUSH brush = CreateSolidBrush(fill);
        HPEN   pen = CreatePen(PS_SOLID, 1, border);
        HGDIOBJ oldBrush = SelectObject(memDC, brush);
        HGDIOBJ oldPen = SelectObject(memDC, pen);

        RoundRect(memDC, r.left, r.top, r.right, r.bottom, S(kRadius, dpi) * 2, S(kRadius, dpi) * 2);

        SelectObject(memDC, oldBrush);
        SelectObject(memDC, oldPen);
        DeleteObject(brush);
        DeleteObject(pen);

        RECT textRect = r;
        textRect.left += S(24, dpi);
        SetTextColor(memDC, RGB(255, 255, 255));
        DrawTextW(memDC, kOptionText[order[i]], -1, &textRect,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    }

    // 底部提示 / 结果
    if (g_frozen.load() && g_chosenOption >= 0) {
        SelectObject(memDC, hResult);
        SetTextColor(memDC, RGB(0x86, 0xd9, 0x92));
        std::wstring text = L"你选择了：" + std::wstring(kOptionText[g_chosenOption]);
        DrawTextW(memDC, text.c_str(), -1, &resultRect,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
    }
    else {
        SelectObject(memDC, hHint);
        SetTextColor(memDC, RGB(0x9b, 0x9b, 0xa1));
        DrawTextW(memDC, L"选项每 1ms 随机变化，点击你想要的那一项即可",
            -1, &resultRect, DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);
    }

    SelectObject(memDC, hOldFont);
    DeleteObject(hQuestion);
    DeleteObject(hOption);
    DeleteObject(hHint);
    DeleteObject(hResult);

    BitBlt(hdc, 0, 0, W, H, memDC, 0, 0, SRCCOPY);

    SelectObject(memDC, oldBmp);
    DeleteObject(bmp);
    DeleteDC(memDC);
    EndPaint(hwnd, &ps);
}

// ---------------------------------------------------------------- 窗口过程
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        timeBeginPeriod(1);                 // 提高计时器精度，让 Sleep(1) 更接近 1ms
        g_worker = std::thread(ShuffleLoop);
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;                            // 已在 WM_PAINT 中双缓冲绘制

    case WM_PAINT:
        PaintWindow(hwnd);
        return 0;

    case WM_DPICHANGED: {
        // 跨显示器 / 系统缩放变化：按系统建议的物理像素尺寸调整窗口
        const RECT* suggested = (const RECT*)lParam;
        SetWindowPos(hwnd, nullptr,
            suggested->left, suggested->top,
            suggested->right - suggested->left,
            suggested->bottom - suggested->top,
            SWP_NOZORDER | SWP_NOACTIVATE);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        if (g_frozen.load()) break;

        const int x = GET_X_LPARAM(lParam);
        const int y = GET_Y_LPARAM(lParam);

        RECT optRects[4], qRect, resultRect;
        GetLayout(hwnd, GetWindowDpi(hwnd), optRects, qRect, resultRect);

        const POINT pt = { x, y };
        for (int i = 0; i < 4; ++i) {
            if (PtInRect(&optRects[i], pt)) {
                // 先停掉洗牌线程，再读取最终顺序，保证结果与用户看到的画面一致
                g_running.store(false);
                if (g_worker.joinable()) g_worker.join();

                {
                    std::lock_guard<std::mutex> lock(g_orderMtx);
                    if (g_forcedOption >= 0) {
                        // 高权限模式：被点中的那一格强制为指定选项，
                        // 其余 3 个选项随机填到剩下的位置。
                        std::vector<int> rest;
                        for (int k = 0; k < 4; ++k) {
                            if (k != g_forcedOption) rest.push_back(k);
                        }
                        std::shuffle(rest.begin(), rest.end(), ClickRng());

                        g_order[i] = g_forcedOption;
                        int r = 0;
                        for (int s = 0; s < 4; ++s) {
                            if (s != i) g_order[s] = rest[r++];
                        }
                        g_chosenOption = g_forcedOption;
                    }
                    else {
                        g_chosenOption = g_order[i];
                    }
                }
                g_chosenSlot = i;
                g_frozen.store(true);
                InvalidateRect(hwnd, nullptr, FALSE);
                break;
            }
        }
        return 0;
    }

    case WM_SETCURSOR:
        SetCursor(LoadCursorW(nullptr, IDC_HAND));
        return TRUE;

    case WM_DESTROY: {
        g_running.store(false);
        if (g_worker.joinable()) g_worker.join();
        timeEndPeriod(1);
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------- 入口
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow)
{
    EnableHighDpiAwareness();               // 必须在创建任何窗口之前

    // 按运行身份决定点击后强制落到的选项（只影响结果，不改变外观）：
    //   TrustedInstaller -> 是小药娘啦！(2)
    //   SYSTEM           -> 想当小南梁！(3)
    //   管理员           -> 是的喵！    (0)
    //   标准             -> 不强制
    switch (DetectRunLevel()) {
    case RunLevel::TrustedInstaller: g_forcedOption = 2; break;
    case RunLevel::System:           g_forcedOption = 3; break;
    case RunLevel::Admin:            g_forcedOption = 0; break;
    case RunLevel::Standard:         g_forcedOption = -1; break;
    }

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"NanLiangQuizWindow";
    RegisterClassExW(&wc);

    const UINT dpi = GetPrimaryDpi();
    RECT rc = { 0, 0, S(kBaseClientW, dpi), S(kBaseClientH, dpi) };
    const DWORD style = WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX;
    AdjustWindowRect(&rc, style, FALSE);

    HWND hwnd = CreateWindowExW(
        0, wc.lpszClassName, L"你是小南梁吗？", style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, hInstance, nullptr);

    if (!hwnd) return 0;

    // 深色标题栏（Win10 1903+；不支持时静默忽略）
    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
