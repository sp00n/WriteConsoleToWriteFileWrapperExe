//////////////////////////////////////////////////////////////////////////////
//
//  Load a program with the WriteConsoleToWriteFileWrapper.dll injected
//  Used to allow to log output from a program that only uses WriteConsoleW calls
//  (y-cruncher)
// 
//  Original was: withdll.cpp from the Detours sample folder
// 
//  Test DetourCreateProcessWithDll function (withdll.cpp).
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include <locale.h>
#include <stdio.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <detours.h>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable:6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)


/**
 * String conversions
 * https://gist.github.com/rosasurfer/33f0beb4b10ff8a8c53d943116f8a872
 * https://stackoverflow.com/a/3999597/973927
 */

// Convert a wide Unicode string to an UTF8 string
std::string utf8_encode(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Convert an UTF8 string to a wide Unicode String
std::wstring utf8_decode(const std::string& str)
{
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// Convert an wide Unicode string to ANSI string
std::string unicode2ansi(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_ACP, 0, &wstr[0], -1, NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Convert an ANSI string to a wide Unicode String
std::wstring ansi2unicode(const std::string& str)
{
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}



//////////////////////////////////////////////////////////////////////////////
//
//  This code verifies that the named DLL has been configured correctly
//  to be imported into the target process.  DLLs must export a function with
//  ordinal #1 so that the import table touch-up magic works.
//
struct ExportContext
{
    BOOL    fHasOrdinal1;
    ULONG   nExports;
};

static BOOL CALLBACK ExportCallback(_In_opt_ PVOID pContext,
    _In_ ULONG nOrdinal,
    _In_opt_ LPCSTR pszSymbol,
    _In_opt_ PVOID pbTarget)
{
    (void)pContext;
    (void)pbTarget;
    (void)pszSymbol;

    ExportContext* pec = (ExportContext*)pContext;

    if (nOrdinal == 1) {
        pec->fHasOrdinal1 = TRUE;
    }
    pec->nExports++;

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//

//////////////////////////////////////////////////////////////////////////////
//

void TypeToString(DWORD Type, char* pszBuffer, size_t cBuffer)
{
    if (Type == MEM_IMAGE) {
        StringCchPrintfA(pszBuffer, cBuffer, "img");
    }
    else if (Type == MEM_MAPPED) {
        StringCchPrintfA(pszBuffer, cBuffer, "map");
    }
    else if (Type == MEM_PRIVATE) {
        StringCchPrintfA(pszBuffer, cBuffer, "pri");
    }
    else {
        StringCchPrintfA(pszBuffer, cBuffer, "%x", Type);
    }
}

void StateToString(DWORD State, char* pszBuffer, size_t cBuffer)
{
    if (State == MEM_COMMIT) {
        StringCchPrintfA(pszBuffer, cBuffer, "com");
    }
    else if (State == MEM_FREE) {
        StringCchPrintfA(pszBuffer, cBuffer, "fre");
    }
    else if (State == MEM_RESERVE) {
        StringCchPrintfA(pszBuffer, cBuffer, "res");
    }
    else {
        StringCchPrintfA(pszBuffer, cBuffer, "%x", State);
    }
}

void ProtectToString(DWORD Protect, char* pszBuffer, size_t cBuffer)
{
    if (Protect == 0) {
        StringCchPrintfA(pszBuffer, cBuffer, "");
    }
    else if (Protect == PAGE_EXECUTE) {
        StringCchPrintfA(pszBuffer, cBuffer, "--x");
    }
    else if (Protect == PAGE_EXECUTE_READ) {
        StringCchPrintfA(pszBuffer, cBuffer, "r-x");
    }
    else if (Protect == PAGE_EXECUTE_READWRITE) {
        StringCchPrintfA(pszBuffer, cBuffer, "rwx");
    }
    else if (Protect == PAGE_EXECUTE_WRITECOPY) {
        StringCchPrintfA(pszBuffer, cBuffer, "rcx");
    }
    else if (Protect == PAGE_NOACCESS) {
        StringCchPrintfA(pszBuffer, cBuffer, "---");
    }
    else if (Protect == PAGE_READONLY) {
        StringCchPrintfA(pszBuffer, cBuffer, "r--");
    }
    else if (Protect == PAGE_READWRITE) {
        StringCchPrintfA(pszBuffer, cBuffer, "rw-");
    }
    else if (Protect == PAGE_WRITECOPY) {
        StringCchPrintfA(pszBuffer, cBuffer, "rc-");
    }
    else if (Protect == (PAGE_GUARD | PAGE_EXECUTE)) {
        StringCchPrintfA(pszBuffer, cBuffer, "g--x");
    }
    else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READ)) {
        StringCchPrintfA(pszBuffer, cBuffer, "gr-x");
    }
    else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READWRITE)) {
        StringCchPrintfA(pszBuffer, cBuffer, "grwx");
    }
    else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_WRITECOPY)) {
        StringCchPrintfA(pszBuffer, cBuffer, "grcx");
    }
    else if (Protect == (PAGE_GUARD | PAGE_NOACCESS)) {
        StringCchPrintfA(pszBuffer, cBuffer, "g---");
    }
    else if (Protect == (PAGE_GUARD | PAGE_READONLY)) {
        StringCchPrintfA(pszBuffer, cBuffer, "gr--");
    }
    else if (Protect == (PAGE_GUARD | PAGE_READWRITE)) {
        StringCchPrintfA(pszBuffer, cBuffer, "grw-");
    }
    else if (Protect == (PAGE_GUARD | PAGE_WRITECOPY)) {
        StringCchPrintfA(pszBuffer, cBuffer, "grc-");
    }
    else {
        StringCchPrintfA(pszBuffer, cBuffer, "%x", Protect);
    }
}

typedef union
{
    struct
    {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
    } ih;

    IMAGE_NT_HEADERS32 ih32;
    IMAGE_NT_HEADERS64 ih64;
} IMAGE_NT_HEADER;

struct SECTIONS
{
    PBYTE   pbBeg;
    PBYTE   pbEnd;
    CHAR    szName[16];
} Sections[256];
DWORD SectionCount = 0;
DWORD Bitness = 0;

PCHAR FindSectionName(PBYTE pbBase, PBYTE& pbEnd)
{
    for (DWORD n = 0; n < SectionCount; n++) {
        if (Sections[n].pbBeg == pbBase) {
            pbEnd = Sections[n].pbEnd;
            return Sections[n].szName;
        }
    }
    pbEnd = NULL;
    return NULL;
}

ULONG PadToPage(ULONG Size)
{
    return (Size & 0xfff)
        ? Size + 0x1000 - (Size & 0xfff)
        : Size;
}

BOOL GetSections(HANDLE hp, PBYTE pbBase)
{
    DWORD beg = 0;
    DWORD cnt = 0;
    SIZE_T done;
    IMAGE_DOS_HEADER idh;

    if (!ReadProcessMemory(hp, pbBase, &idh, sizeof(idh), &done) || done != sizeof(idh)) {
        return FALSE;
    }

    if (idh.e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    IMAGE_NT_HEADER inh;
    if (!ReadProcessMemory(hp, pbBase + idh.e_lfanew, &inh, sizeof(inh), &done) || done != sizeof(inh)) {
        printf("No Read\n");
        return FALSE;
    }

    if (inh.ih.Signature != IMAGE_NT_SIGNATURE) {
        printf("No NT\n");
        return FALSE;
    }

    beg = idh.e_lfanew
        + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)
        + inh.ih.FileHeader.SizeOfOptionalHeader;
    cnt = inh.ih.FileHeader.NumberOfSections;
    Bitness = (inh.ih32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 32 : 64;
#if 0
    printf("%d %d count=%d\n", beg, Bitness, cnt);
#endif

    IMAGE_SECTION_HEADER ish;
    for (DWORD n = 0; n < cnt; n++) {
        if (!ReadProcessMemory(hp, pbBase + beg + n * sizeof(ish), &ish, sizeof(ish), &done) || done != sizeof(ish)) {
            printf("No Read\n");
            return FALSE;
        }
        Sections[n].pbBeg = pbBase + ish.VirtualAddress;
        Sections[n].pbEnd = pbBase + ish.VirtualAddress + PadToPage(ish.Misc.VirtualSize);
        memcpy(Sections[n].szName, ish.Name, sizeof(ish.Name));
        Sections[n].szName[sizeof(ish.Name)] = '\0';
#if 0
        printf("--- %p %s\n", Sections[n].pbBeg, Sections[n].szName);
#endif
    }
    SectionCount = cnt;

    return TRUE;
}


//////////////////////////////////////////////////////////////////////// main.
//
int CDECL main(int argc, char** argv)
{
    /*
    std::cout << "LC_ALL:   " << setlocale(LC_ALL, NULL) << std::endl;
    std::cout << "LC_CTYPE: " << setlocale(LC_CTYPE, NULL) << std::endl;

    char* res = setlocale(LC_ALL, ".UTF8");
    if (res == nullptr) puts("setlocale failed");
    else printf("New locale: %s\n", res);
    */

    SetConsoleOutputCP(CP_UTF8);    // Tells terminal to use UTF8
    setlocale(LC_ALL, ".UTF8");     // Tells C runtime to use UTF8


    // This is the DLL file we want to inject
    // It needs to be in the same directory as this wrapper exe and it also needs a 32bit equivalent
    const CHAR* dllName = "WriteConsoleToWriteFileWrapper64.dll";
    CHAR currentExePath[MAX_PATH];
    CHAR dllPath[1024];


    // This is the path where the wrapper file was called from, so in most cases not the directory of the wrapper file itself
    const std::string currentPath = std::filesystem::current_path().string();
    printf("\n\nCurrent working directory (currentPath): %s\n", currentPath.c_str());

    
    // This returns the path of this wrapper exe file (including the exe file)
    if (!GetModuleFileNameA(NULL, currentExePath, MAX_PATH)) {
        printf("Cannot GetModuleFileNameA. (Error %d)\n", GetLastError());
        return 9001;
    }
    printf("GetModuleFileNameA (currentExePath):     %s\n", currentExePath);

    
    // Since the DLL file is in the same place as this exe file, replace the exe file path with the dll file name
    const std::string dllPathMerged = std::filesystem::path{ currentExePath }.replace_filename(dllName).string();
    printf("dllPathMerged:                           %s\n", dllPathMerged.c_str());

    if (!GetFullPathNameA(dllPathMerged.c_str(), ARRAYSIZE(dllPath), dllPath, NULL)) {
        printf("Error - GetFullPathNameA: not a valid path name: %s\n", dllPathMerged.c_str());
        return 9002;
    }
    printf("GetFullPathNameA (dllPath):              %s\n", dllPath);


    if (!std::filesystem::exists(dllPath)) {
        printf("Error - filesystem::exists: file not found: %s\n", dllPath);
    }
    printf("filesystem::exists successful:           %s\n", dllPath);

    LPCSTR dllPathFinal;
    DWORD c = (DWORD)strlen(dllPath) + 1;
    PCHAR psz = new CHAR[c];
    StringCchCopyA(psz, c, dllPath);
    dllPathFinal = psz;

    HMODULE handleDll = LoadLibraryExA(dllPathFinal, NULL, DONT_RESOLVE_DLL_REFERENCES);

    if (handleDll == NULL) {
        printf("Error - LoadLibraryExA: %s failed to load (error %ld).\n", dllPathFinal, GetLastError());
        return 9003;
    }

    printf("LoadLibraryExA succeeded for:            %s\n", dllPathFinal);


    ExportContext ec;
    ec.fHasOrdinal1 = FALSE;
    ec.nExports = 0;
    DetourEnumerateExports(handleDll, &ec, ExportCallback);
    FreeLibrary(handleDll);

    if (!ec.fHasOrdinal1) {
        printf("WriteConsoleToWriteFileWrapper.exe: Error: %s does not export ordinal #1.\n", dllPathFinal);
        printf("             See help entry DetourCreateProcessWithDllEx in Detours.chm.\n");
        return 9004;
    }


    /*
    int arg = 1;
    for (; arg < argc && (argv[arg][0] == '-' || argv[arg][0] == '/'); arg++) {

        CHAR* argn = argv[arg] + 1;
        CHAR* argp = argn;
        while (*argp && *argp != ':' && *argp != '=')
            argp++;
        if (*argp == ':' || *argp == '=')
            *argp++ = '\0';
    }
    */


    // Parse the command line to get the name of exe to inject and the name of the log file
    int numberOfArgs;
    LPWSTR commandLine = GetCommandLineW();
    LPWSTR* szArglist = CommandLineToArgvW(commandLine, &numberOfArgs);
    std::vector<std::string> argumentListUtf8(numberOfArgs);
    std::vector<const char*> argumentList(numberOfArgs);

    wprintf(L"\n\ncommandLine: %ls\n\n", commandLine);
    //wprintf(L"szArglist[0]:       %ls\n", szArglist[0]);
    printf("argv[0]:            %s\n", argv[0]);
    printf("argv[1]:            %s\n", argv[1]);
    printf("argv[2]:            %s\n", argv[2]);
    printf("argv[3]:            %s\n", argv[3]);
    printf("argv[4]:            %s\n", argv[4]);
    printf("argv[5]:            %s\n", argv[5]);

    // Convert the wide string argument list to utf8
    for (int i = 0; i < numberOfArgs; i++) {
        argumentListUtf8[i] = utf8_encode(szArglist[i]);
        argumentList[i] = argumentListUtf8[i].c_str();
    }

    //printf("argumentListUtf8[0]: %s\n", argumentListUtf8[0]);
    printf("argumentList[0]:    %s\n", argumentList[0]);
    printf("argumentList[1]:    %s\n", argumentList[1]);
    printf("argumentList[2]:    %s\n", argumentList[2]);
    printf("argumentList[3]:    %s\n", argumentList[3]);
    printf("argumentList[4]:    %s\n", argumentList[4]);
    printf("argumentList[5]:    %s\n", argumentList[5]);

    //exit(0);


    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;
    CHAR szCommand[2048];
    CHAR exeToRun[MAX_PATH];
    CHAR finalExePath[MAX_PATH] = "\0";

    DWORD dwFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);

    szCommand[0] = L'\0';

    SetLastError(0);

    // Search for the exe file to inject into
    StringCchCopyA(exeToRun, sizeof(exeToRun), argv[1]);
    printf("exeToRun:                                %s\n", exeToRun);

    SearchPathA(NULL, exeToRun, ".exe", ARRAYSIZE(finalExePath), finalExePath, NULL);
    printf("SearchPathA (finalExePath):              %s\n", finalExePath);
    


    // Create the command line
    int arg = 1;
    for (; arg < argc; arg++) {
        if (strchr(argumentList[arg], ' ') != NULL || strchr(argumentList[arg], '\t') != NULL) {
            StringCchCatA(szCommand, sizeof(szCommand), "\"");
            StringCchCatA(szCommand, sizeof(szCommand), argumentList[arg]);
            StringCchCatA(szCommand, sizeof(szCommand), "\"");
        }
        else {
            StringCchCatA(szCommand, sizeof(szCommand), argumentList[arg]);
        }

        if (arg + 1 < argc) {
            StringCchCatA(szCommand, sizeof(szCommand), " ");
        }
    }

    printf("\nThe new command line for Detours:\n%s\n\n", szCommand);

    /*
    int wideCharCount = MultiByteToWideChar(CP_UTF8, 0, dllPathFinal, -1, NULL, 0);
    wchar_t* dllPathWide = new wchar_t[wideCharCount];
    MultiByteToWideChar(CP_UTF8, 0, szCommand, -1, dllPathWide, wideCharCount);

    int ansiCharCount = WideCharToMultiByte(CP_ACP, 0, dllPathWide, -1, NULL, 0, NULL, NULL);
    char* dllPathAnsi = new char[ansiCharCount];
    WideCharToMultiByte(CP_ACP, 0, dllPathWide, -1, dllPathAnsi, ansiCharCount, NULL, NULL);
    //*/


    /*
    std::string dllPathString(dllPathFinal);
    int sizeNeededWide = MultiByteToWideChar(CP_UTF8, 0, &dllPathString[0], (int)dllPathString.size(), NULL, 0);
    std::wstring dllPathWide(sizeNeededWide, 0);
    MultiByteToWideChar(CP_UTF8, 0, &dllPathString[0], (int)dllPathString.size(), &dllPathWide[0], sizeNeededWide);
    
    std::wstring dllPathWideString(dllPathWide);
    int sizeNeededAnsi = WideCharToMultiByte(CP_ACP, 0, &dllPathWideString[0], -1, NULL, 0, NULL, NULL);
    std::string dllPathAnsi(sizeNeededAnsi, 0);
    WideCharToMultiByte(CP_ACP, 0, &dllPathWideString[0], (int)dllPathWideString.size(), &dllPathAnsi[0], sizeNeededAnsi, NULL, NULL);
    //*/

    /*
    std::wstring dllPathWide = utf8_decode(dllPathFinal);
    std::string dllPathAnsi = unicode2ansi(dllPathWide);
    //*/

    /*
    wprintf(L"\nThe new Wide dllPathWide: %s", dllPathWide.c_str());
    printf("\nThe new ANSI dllPathAnsi: %s\n\n", dllPathAnsi.c_str());
    //*/

    //exit(0);

    if (!DetourCreateProcessWithDllExA(finalExePath, szCommand,     // if (!DetourCreateProcessWithDllExA(finalExePath, szCommand,
        NULL, NULL, TRUE, dwFlags, NULL, NULL,
        &startupInfo, &processInfo, dllPathFinal, NULL)) {
        DWORD dwError = GetLastError();
        printf("DetourCreateProcessWithDllEx failed: %ld\n", dwError);
        ExitProcess(9009);
    }

    printf("DetourCreateProcessWithDllEx succeeded for %s\n                                       and %s\n", finalExePath, dllPathFinal);
    printf("WriteConsoleToWriteFileWrapper.exe:\nStarting: %s\n    with: %s\n", szCommand, dllPathFinal);
    
    fflush(stdout);

    //delete[] dllPathWide;
    //delete[] dllPathAnsi;


    ResumeThread(processInfo.hThread);

    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD dwResult = 0;
    if (!GetExitCodeProcess(processInfo.hProcess, &dwResult)) {
        printf("WriteConsoleToWriteFileWrapper.exe: GetExitCodeProcess failed: %ld\n", GetLastError());
        return 9010;
    }
    dllPathFinal = NULL;
    delete dllPathFinal;


    return dwResult;
}
//
///////////////////////////////////////////////////////////////// End of File.
