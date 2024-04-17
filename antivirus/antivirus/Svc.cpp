#include <windows.h>
#include <iostream>
#include <string>
#include <Wtsapi32.h>

//#pragma comment(lib, "advapi32.lib")

#define serviceName TEXT("antivirus2")
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;

BOOL CustomCreateProcess(DWORD wtsSession, DWORD& dwBytes);
//VOID ReportServiceError(const wchar_t* message);
DWORD WINAPI ControlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);
VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR* lpszArgv);

BOOL CustomCreateProcess(DWORD wtsSessionId, DWORD& dwBytes) {
    HANDLE userToken;
    PROCESS_INFORMATION pi{};
    STARTUPINFO si{};
    si.cb = sizeof(STARTUPINFO);
    WCHAR path[] = L"C:\\Windows\\System32\\notepad.exe";

    if (!WTSQueryUserToken(wtsSessionId, &userToken))
        return FALSE;

    if (!CreateProcessAsUser(userToken, NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(userToken);
        return FALSE;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(userToken);
    return TRUE;
}

//VOID //ReportServiceError(const wchar_t* message) {
//    HANDLE hEventSource = RegisterEventSource(NULL, serviceName);
//    if (hEventSource != NULL) {
//        const LPCWSTR szStrings[2] = { serviceName, message };
//        ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 2, 0, const_cast<LPCWSTR*>(szStrings), NULL);
//
//        DeregisterEventSource(hEventSource);
//    }
//}

DWORD WINAPI ControlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    DWORD dwBytes = NULL;
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
    case SERVICE_CONTROL_SHUTDOWN:
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        break;
    case SERVICE_CONTROL_SESSIONCHANGE:
        if (lpEventData != nullptr && dwEventType == WTS_SESSION_LOGON || dwEventType == WTS_SESSION_CREATE || dwEventType == WTS_REMOTE_CONNECT) {
            WTSSESSION_NOTIFICATION* sessionNotification = static_cast<WTSSESSION_NOTIFICATION*>(lpEventData);
            CustomCreateProcess(sessionNotification->dwSessionId, dwBytes);
        }
        break;
    default:
        break;
    }
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
    return NO_ERROR;
}

VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR* lpszArgv) {
    DWORD dwBytes = 0;
    serviceStatusHandle = RegisterServiceCtrlHandlerEx(serviceName, (LPHANDLER_FUNCTION_EX)ControlHandlerEx, NULL);
    if (serviceStatusHandle == NULL) {
        //ReportServiceError(L"Failed to register service control handler");
        return;
    }
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE;
    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    std::wcout << L"Service is running." << std::endl;

    PWTS_SESSION_INFO pWtsSessions = nullptr;
    DWORD dwSessionCount;
    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pWtsSessions, &dwSessionCount)) {
        for (DWORD i = 0; i < dwSessionCount; ++i) {
            if (pWtsSessions[i].SessionId != 0)
                CustomCreateProcess(pWtsSessions[i].SessionId, dwBytes);
        }
        WTSFreeMemory(pWtsSessions);
    }

    while (serviceStatus.dwCurrentState != SERVICE_STOPPED) {
        Sleep(1000);
    }
}

int main(int argc, CHAR* argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)serviceName, ServiceMain },
        { NULL, NULL }
    };

    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        SC_HANDLE schService = OpenService(schSCManager, serviceName, SERVICE_QUERY_STATUS);
        if (schService) {
            std::wcout << L"Service already exists." << std::endl;
            CloseServiceHandle(schService);
        }
        else {
            schService = CreateService(schSCManager, serviceName, serviceName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, NULL, NULL);
            if (schService) {
                CloseServiceHandle(schService);
                std::wcout << L"Service installed successfully." << std::endl;
            }
            else {
                std::wstring errorMessage = L"Failed to create service: " + std::to_wstring(GetLastError());
                std::wcerr << "Error: " << errorMessage << std::endl;
                //ReportServiceError(errorMessage.c_str());
            }
        }
        CloseServiceHandle(schSCManager);
    }
    else {
        std::wstring errorMessage = L"Failed to open service control manager: " + std::to_wstring(GetLastError());
        std::wcerr << "Error: " << errorMessage << std::endl;
        //ReportServiceError(errorMessage.c_str());
    }

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        std::wstring errorMessage = L"StartServiceCtrlDispatcher failed: " + std::to_wstring(GetLastError());
        //ReportServiceError(errorMessage.c_str());
        return 1;
    }

    return 0;
}
