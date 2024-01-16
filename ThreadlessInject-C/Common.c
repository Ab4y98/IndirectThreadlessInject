#include <Windows.h>

#include "Common.h"



BOOL InitIndirectSyscalls(OUT PNT_API Nt) 
{

    if (Nt->bInit)
        return TRUE;

    if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &Nt->NtAllocateVirtualMemory)) {
        //printf("[!] Failed To Initialize \"NtAllocateVirtualMemory\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
        return FALSE;
    }

    if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &Nt->NtProtectVirtualMemory)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtMapViewOfSection\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &Nt->NtCreateThreadEx)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtProtectVirtualMemory\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &Nt->NtWaitForSingleObject)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtUnmapViewOfSection\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!FetchNtSyscall(NtWriteVirtualMemory_CRC32, &Nt->NtWriteVirtualMemory)) {
        return FALSE;
    }

    if (!FetchNtSyscall(NtOpenProcess_CRC32, &Nt->NtOpenProcess)) {
        return FALSE;
    }


#ifdef DEBUG
    PRINT("[V] NtOpenSection [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtOpenSection.dwSSn, Nt->NtOpenSection.pSyscallInstAddress);
    PRINT("[V] NtMapViewOfSection [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtMapViewOfSection.dwSSn, Nt->NtMapViewOfSection.pSyscallInstAddress);
    PRINT("[V] NtProtectVirtualMemory [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtProtectVirtualMemory.dwSSn, Nt->NtProtectVirtualMemory.pSyscallInstAddress);
    PRINT("[V] NtUnmapViewOfSection [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtUnmapViewOfSection.dwSSn, Nt->NtUnmapViewOfSection.pSyscallInstAddress);
    PRINT("[V] NtAllocateVirtualMemory [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtAllocateVirtualMemory.dwSSn, Nt->NtAllocateVirtualMemory.pSyscallInstAddress);
    PRINT("[V] NtDelayExecution [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtDelayExecution.dwSSn, Nt->NtDelayExecution.pSyscallInstAddress);
#endif

    Nt->bInit = TRUE;

    return TRUE;
}



/*
*   An implementation of the 'Cyclic redundancy check' string hashing algorithm
*   From :  https://stackoverflow.com/a/21001712
*/

UINT32 CRC32B(LPCSTR cString) 
{

    UINT32      uMask   = 0x00,
                uHash   = 0xFFFFFFFF;
    INT         i       = 0x00;

    while (cString[i] != 0) {

        uHash = uHash ^ (UINT32)cString[i];

        for (int ii = 0; ii < 8; ii++) {

            uMask = -1 * (uHash & 1);
            uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & uMask);
        }

        i++;
    }

    return ~uHash;
}


/*
*   Custom random number generator using XORshift algorithm
*/
unsigned int GenerateRandomInt() 
{
    static unsigned int state = 123456789;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}


// replaces the 'wcscat' function
VOID Wcscat(IN WCHAR* pDest, IN WCHAR* pSource) 
{

    while (*pDest != 0)
        pDest++;

    while (*pSource != 0) {
        *pDest = *pSource;
        pDest++;
        pSource++;
    }

    *pDest = 0;
}



// replaces the 'memcpy' function
VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength) 
{

    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--)
        *D++ = *S++;
}


// replaces 'memset' while compiling
extern void* __cdecl memset(void*, int, size_t);

#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
    unsigned char* p = (unsigned char*)pTarget;
    while (cbTarget-- > 0) {
        *p++ = (unsigned char)value;
    }
    return pTarget;
}


// replaces 'strrchr' while compiling. 'strrchr' is called from the 'GET_FILENAME' macro located in the 'Debug.h' file
extern void* __cdecl strrchr(const char*, int);

#pragma intrinsic(strrchr)
#pragma function(strrchr)
char* strrchr(const char* str, int c) {
    char* last_occurrence = NULL;  
    while (*str) {
        if (*str == c) {
            last_occurrence = (char*)str;  
        }
        str++;
    }

    return last_occurrence;
}