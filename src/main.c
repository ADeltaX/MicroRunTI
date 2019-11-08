#include <shlwapi.h>
#include <TlHelp32.h>
#include <UserEnv.h>

INT GetProcessIdOfName(WCHAR* name)
{
	INT pid = -1;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (lstrcmpi(entry.szExeFile, name) == 0)
			{
				pid = entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return pid;
}

WCHAR* GetExecutablePath()
{
	WCHAR* buf[MAX_PATH];

	GetModuleFileName(NULL, buf, MAX_PATH);

	return buf;
}

BOOL StartTiService()
{
	BOOL wasDisabled = FALSE;
	QUERY_SERVICE_CONFIG SvcConfig = {0};
	SC_HANDLE hSvcMgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

	SC_HANDLE hSvc = OpenService(hSvcMgr, L"TrustedInstaller",
		SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_START);

	UINT dummy = 0;
	DWORD dwBytesNeeded;
	LPQUERY_SERVICE_CONFIG lpqscBuf = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, 4096);
	if (!QueryServiceConfig(hSvc, lpqscBuf, 4096, &dwBytesNeeded))
		return FALSE;

	wasDisabled = (SvcConfig.dwStartType == SERVICE_DISABLED);


	if (wasDisabled)
	{
		if (!ChangeServiceConfig(hSvc, SERVICE_NO_CHANGE,
			SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
			NULL, NULL, NULL, NULL, NULL, NULL, NULL)) 
			return FALSE;
	}

	StartService(hSvc, 0, NULL);

	if (wasDisabled)
	{
		if (!ChangeServiceConfig(hSvc, SERVICE_NO_CHANGE,
			SERVICE_DISABLED, SERVICE_NO_CHANGE,
			NULL, NULL, NULL, NULL, NULL, NULL, NULL)) 
			return FALSE;
	}
	
	LocalFree(lpqscBuf);
	CloseServiceHandle(hSvc);
	CloseServiceHandle(hSvcMgr);

	return TRUE;
}

void RunWithToken(WCHAR* procName, WCHAR* path, WCHAR* cmdLine, BOOL forceTokenUseActiveSessionID)
{
	WCHAR* ultrabuf = path;

	INT procId = GetProcessIdOfName(procName);
	if (procId == -1)
		return;

	HANDLE currProc = GetCurrentProcess();
	HANDLE hToken;

	if (!OpenProcessToken(currProc, TOKEN_ALL_ACCESS, &hToken))
		return;

	LUID luid;
	if (!LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid))
		return;

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!(AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) & (GetLastError() == 0)))
		return;

	CloseHandle(hToken);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
	if (!hProc)
		return;

	HANDLE hTokenToCopyFrom;
	if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTokenToCopyFrom))
		return;

	HANDLE nhToken;
	if (!DuplicateTokenEx(hTokenToCopyFrom, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &nhToken))
		return;

	if (forceTokenUseActiveSessionID)
	{
		DWORD SID = WTSGetActiveConsoleSessionId();
		if (!SetTokenInformation(nhToken, TokenSessionId, &SID, sizeof(DWORD)))
			return;
	}

	LPVOID lpEnvironment;
	if (!CreateEnvironmentBlock(&lpEnvironment, hTokenToCopyFrom, TRUE))
		return;

	STARTUPINFO si = {0};
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = L"winsta0\\default";
	PROCESS_INFORMATION pi = {0};
	
	if (!CreateProcessWithTokenW(nhToken, LOGON_WITH_PROFILE, path, cmdLine,
		(NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT),
		lpEnvironment, NULL, &si, &pi))
	{
		if (!CreateProcessAsUser(nhToken, path, cmdLine, NULL, NULL, FALSE,
			(NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT),
			lpEnvironment, NULL, &si, &pi))
			return;
	}

	CloseHandle(hTokenToCopyFrom);
	CloseHandle(nhToken);
	CloseHandle(si.hStdError);
	CloseHandle(si.hStdInput);
	CloseHandle(si.hStdOutput);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	DestroyEnvironmentBlock(lpEnvironment);
}

void main()
{
	int argc;
	WCHAR **argv = CommandLineToArgvW(GetCommandLine(), &argc);

	if(argv)
	{
		if(argc >= 0)
		{
			BOOL SwitchTI = lstrcmpi(argv[0], L"/STI") == 0;
			if (!SwitchTI)
			{
				if (StartTiService())
				{
					WCHAR* path = GetExecutablePath();
					WCHAR uwu[MAX_PATH];
					lstrcpy(uwu, path);

					RunWithToken(L"winlogon.exe", uwu, L"/STI", FALSE);
				}
			}
			else
			{
				RunWithToken(L"TrustedInstaller.exe", L"cmd.exe", L"", TRUE);
			}

		}

		LocalFree(argv);
	}

	ExitProcess(0);
}