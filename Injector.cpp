#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

#define IDC_SELECT_PROCESS 101
#define IDC_BROWSE_DLL     102
#define IDC_INJECT_DLL     103
#define IDC_LOG            400
#define IDC_PROCESS_LIST   200
#define IDC_FILTER_TAB     300

DWORD g_targetPID = 0;
char  g_dllPath[MAX_PATH] = "";
HWND  g_hLog = NULL; 


void AppendLog(HWND hLog, const char* msg)
{
    int len = GetWindowTextLength(hLog);
    SendMessage(hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(hLog, EM_REPLACESEL, FALSE, (LPARAM)msg);
}

void AppendLogLine(HWND hLog, const char* msg)
{
    char buffer[1024];
    sprintf_s(buffer, sizeof(buffer), "%s\r\n", msg);
    AppendLog(hLog, buffer);
}


bool InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, processID);
    if (!hProcess) {
        AppendLogLine(g_hLog, "Error: Failed to open target process.");
        return false;
    }

    size_t dllPathLen = strlen(dllPath) + 1;
    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuffer) {
        AppendLogLine(g_hLog, "Error: Failed to allocate memory in target process.");
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuffer, dllPath, dllPathLen, NULL)) {
        AppendLogLine(g_hLog, "Error: Failed to write memory in target process.");
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        AppendLogLine(g_hLog, "Error: Failed to get address of LoadLibraryA.");
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryA,
        pRemoteBuffer, 0, NULL);
    if (!hThread) {
        AppendLogLine(g_hLog, "Error: Failed to create remote thread.");
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

BOOL CALLBACK EnumApplicationsProc(HWND hwnd, LPARAM lParam)
{
    if (!IsWindowVisible(hwnd))
        return TRUE;
    if (GetWindow(hwnd, GW_OWNER) != NULL)
        return TRUE;
    int len = GetWindowTextLength(hwnd);
    if (len == 0)
        return TRUE;
    char title[256];
    GetWindowText(hwnd, title, sizeof(title));
    if (strcmp(title, "Program Manager") == 0)
        return TRUE;
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    HWND hList = (HWND)lParam;
    char item[512];
    sprintf_s(item, sizeof(item), "%s (PID: %d)", title, pid);
    int index = (int)SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)item);
    SendMessage(hList, LB_SETITEMDATA, index, (LPARAM)pid);
    return TRUE;
}

BOOL CALLBACK EnumWindowsWindowsProc(HWND hwnd, LPARAM lParam)
{
    if (!IsWindowVisible(hwnd))
        return TRUE;
    int len = GetWindowTextLength(hwnd);
    if (len == 0)
        return TRUE;
    char title[256];
    GetWindowText(hwnd, title, sizeof(title));
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    HWND hList = (HWND)lParam;
    char item[512];
    sprintf_s(item, sizeof(item), "%s (PID: %d)", title, pid);
    int index = (int)SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)item);
    SendMessage(hList, LB_SETITEMDATA, index, (LPARAM)pid);
    return TRUE;
}

void PopulateListBox(HWND hList, int filterIndex)
{
    SendMessage(hList, LB_RESETCONTENT, 0, 0);
    if (filterIndex == 0) {
        EnumWindows(EnumApplicationsProc, (LPARAM)hList);
    }
    else if (filterIndex == 1) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &pe32)) {
                do {
                    DWORD sessionId = 0;
                    ProcessIdToSessionId(pe32.th32ProcessID, &sessionId);
                    if (sessionId == 0)
                        continue;
                    char item[512];
                    sprintf_s(item, sizeof(item), "%s (PID: %d)", pe32.szExeFile, pe32.th32ProcessID);
                    int index = (int)SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)item);
                    SendMessage(hList, LB_SETITEMDATA, index, (LPARAM)pe32.th32ProcessID);
                } while (Process32Next(hSnap, &pe32));
            }
            CloseHandle(hSnap);
        }
    }
    else if (filterIndex == 2) {
        EnumWindows(EnumWindowsWindowsProc, (LPARAM)hList);
    }
    SendMessage(hList, LB_SETCURSEL, 0, 0);
}

LRESULT CALLBACK ProcessDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    static HWND hTab = NULL;
    static HWND hList = NULL;
    switch (message)
    {
    case WM_CREATE:
    {
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
        hTab = CreateWindowEx(0, WC_TABCONTROL, "",
            WS_CHILD | WS_VISIBLE | TCS_TABS,
            10, 5, 320, 25,
            hDlg, (HMENU)IDC_FILTER_TAB, hInst, NULL);
        TCITEM tie = { 0 };
        tie.mask = TCIF_TEXT;
        tie.pszText = (LPSTR)"Applications";
        TabCtrl_InsertItem(hTab, 0, &tie);
        tie.pszText = (LPSTR)"Processes";
        TabCtrl_InsertItem(hTab, 1, &tie);
        tie.pszText = (LPSTR)"Windows";
        TabCtrl_InsertItem(hTab, 2, &tie);
        hList = CreateWindow("LISTBOX", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY | WS_VSCROLL,
            10, 35, 320, 360,
            hDlg, (HMENU)IDC_PROCESS_LIST, hInst, NULL);
        PopulateListBox(hList, 0);
        break;
    }
    case WM_NOTIFY:
    {
        NMHDR* nmhdr = (NMHDR*)lParam;
        if (nmhdr->hwndFrom == GetDlgItem(hDlg, IDC_FILTER_TAB))
        {
            if (nmhdr->code == TCN_SELCHANGE)
            {
                int sel = TabCtrl_GetCurSel(GetDlgItem(hDlg, IDC_FILTER_TAB));
                PopulateListBox(hList, sel);
                return 0;
            }
        }
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_PROCESS_LIST && HIWORD(wParam) == LBN_DBLCLK)
        {
            int sel = (int)SendMessage(hList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR)
                g_targetPID = (DWORD)SendMessage(hList, LB_GETITEMDATA, sel, 0);
            DestroyWindow(hDlg);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hDlg);
        return 0;
    }
    return DefWindowProc(hDlg, message, wParam, lParam);
}

void SelectProcessDialog(HWND parent)
{
    HINSTANCE hInst = GetModuleHandle(NULL);
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = ProcessDialogProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "ProcessDialogClass";
    RegisterClass(&wc);

    HWND hDlg = CreateWindowEx(
        WS_EX_DLGMODALFRAME,
        "ProcessDialogClass",
        "Select Process",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 350, 450,
        parent, NULL, hInst, NULL
    );
    if (!hDlg)
        return;

    RECT rcParent, rcDlg;
    GetWindowRect(parent, &rcParent);
    GetWindowRect(hDlg, &rcDlg);
    int posX = rcParent.left + (((rcParent.right - rcParent.left) - (rcDlg.right - rcDlg.left)) / 2);
    int posY = rcParent.top + (((rcParent.bottom - rcParent.top) - (rcDlg.bottom - rcDlg.top)) / 2) + 50;
    SetWindowPos(hDlg, NULL, posX, posY, 350, 450, SWP_NOZORDER);

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    MSG msg;
    while (IsWindow(hDlg))
    {
        while (PeekMessage(&msg, hDlg, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(10);
    }
    // Log selected PID.
    char msgBuf[64];
    sprintf_s(msgBuf, sizeof(msgBuf), "Selected PID: %d", g_targetPID);
    AppendLogLine(g_hLog, msgBuf);
}

void BrowseForDLL(HWND hwnd)
{
    OPENFILENAME ofn;
    char szFile[MAX_PATH] = { 0 };
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.lpstrTitle = "Select DLL to Inject";
    ofn.Flags = OFN_FILEMUSTEXIST;
    if (GetOpenFileName(&ofn))
    {
        strcpy_s(g_dllPath, sizeof(g_dllPath), szFile);
        char buffer[512];
        sprintf_s(buffer, sizeof(buffer), "DLL Selected: %s", g_dllPath);
        AppendLogLine(g_hLog, buffer);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        const int margin = 10;
        const int btnWidth = 110;
        const int btnHeight = 30;
        CreateWindow("BUTTON", "Select Process", WS_CHILD | WS_VISIBLE,
            margin, margin, btnWidth, btnHeight,
            hwnd, (HMENU)IDC_SELECT_PROCESS,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        CreateWindow("BUTTON", "Browse DLL", WS_CHILD | WS_VISIBLE,
            margin + btnWidth + margin, margin, btnWidth, btnHeight,
            hwnd, (HMENU)IDC_BROWSE_DLL,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        CreateWindow("BUTTON", "Inject DLL", WS_CHILD | WS_VISIBLE,
            margin + (btnWidth + margin) * 2, margin, btnWidth, btnHeight,
            hwnd, (HMENU)IDC_INJECT_DLL,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        int logY = margin + btnHeight + margin;
        int logWidth = 370 - margin * 2;
        int logHeight = 250 - logY - margin;
        g_hLog = CreateWindow("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            margin, logY, logWidth, logHeight,
            hwnd, (HMENU)IDC_LOG,
            ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        break;
    }
    case WM_NCHITTEST:
    {
        LRESULT hit = DefWindowProc(hwnd, msg, wParam, lParam);
        if (hit == HTCLIENT)
            hit = HTCAPTION;
        return hit;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_SELECT_PROCESS:
            SelectProcessDialog(hwnd);
            break;
        case IDC_BROWSE_DLL:
            BrowseForDLL(hwnd);
            break;
        case IDC_INJECT_DLL:
            if (g_targetPID == 0) {
                AppendLogLine(g_hLog, "Error: No target process selected.");
                break;
            }
            if (strlen(g_dllPath) == 0) {
                AppendLogLine(g_hLog, "Error: No DLL selected.");
                break;
            }
            if (InjectDLL(g_targetPID, g_dllPath))
                AppendLogLine(g_hLog, "Injection successful.");
            else
                AppendLogLine(g_hLog, "Injection failed.");
            break;
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd)
{
    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_TAB_CLASSES };
    InitCommonControlsEx(&icex);

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "InjectorWindowClass";
    RegisterClass(&wc);

    int winWidth = 387;
    int winHeight = 290;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenW - winWidth) / 2;
    int posY = (screenH - winHeight) / 2;

    HWND hwnd = CreateWindow("InjectorWindowClass", "DLL Injector",
        (WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME),
        posX, posY, winWidth, winHeight,
        NULL, NULL, hInst, NULL);
    if (!hwnd)
        return -1;

    ShowWindow(hwnd, nShowCmd);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}