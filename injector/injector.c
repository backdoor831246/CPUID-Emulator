#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

DWORD find_pid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

int wmain(int argc, wchar_t* argv[]) {

    if (argc < 3) {
        wprintf(L"injector.exe <process.exe> <dll_path>\n\n");
        return 0;
    }

    const wchar_t* proc_name = argv[1];
    const wchar_t* dll_path = argv[2];

    DWORD pid = find_pid(proc_name);

    if (!pid) {
        wprintf(L"Process not found: %s\n", proc_name);
        return 1;
    }

    wprintf(L"Found PID: %lu\n", pid);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        wprintf(L"OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    SIZE_T path_len = (wcslen(dll_path) + 1) * sizeof(wchar_t);

    LPVOID remote_mem = VirtualAllocEx(
        hProc,
        NULL,
        path_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remote_mem) {
        wprintf(L"VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    WriteProcessMemory(
        hProc,
        remote_mem,
        dll_path,
        path_len,
        NULL
    );

    LPVOID load_lib = GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"),
        "LoadLibraryW"
    );

    HANDLE hThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)load_lib,
        remote_mem,
        0,
        NULL
    );

    if (!hThread) {
        wprintf(L"CreateRemoteThread failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    WaitForSingleObject(hThread, 5000);

    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);

    wprintf(L"Thread exit code: %lu\n", exit_code);
    wprintf(L"Injected successfully into PID %lu\n", pid);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return 0;
}