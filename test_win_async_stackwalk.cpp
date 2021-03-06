/*
 * The MIT License
 *
 * Copyright 2014 Kiyofumi Kondoh
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "stdafx.h"

#include <dbghelp.h>
#pragma comment(lib,"dbghelp.lib")
#include <tlhelp32.h>

// NtQueryInformationThread
#include <winternl.h>

#if defined(_MSC_VER)
#include <crtdbg.h>
#endif // defined(_MSC_VER)

/*
TODO

http://en.wikipedia.org/wiki/Win32_Thread_Information_Block
thread's stack in range between StackBase and StackLimit.

memcache PREAD_PROCESS_MEMORY_ROUTINE
* capture dll by ReadProcessMemory.

for async
* snapshot stack by ReadProcessMemory.

and then async StackWalk64

*/


#define USE_GETTHREADCONTEXT 1
#define MESURE_TIME 1

#if MESURE_TIME
static DWORD    s_dwTimeReadMemory = 0;
static DWORD    s_dwTimeGetThreadContext = 0;
static DWORD    s_dwTimeStackWalk = 0;
static DWORD    s_dwTimeGetStack = 0;
#endif // MESURE_TIME

#include <string>

class kkRemoteAsyncStackwalk
{
public:
    bool    attachProcess( const DWORD dwProcessId );
    bool    detachProcess( void );
    bool    isWow64Process( void ) const { return (m_bIsWow64)?(true):(false); }

    bool    initDebugHelp();
    bool    termDebugHelp();

    bool    captureStack( HANDLE hThread, LPVOID pContextRecord );
    bool    getStackTrace( HANDLE hThread, DWORD64* pStackArray, const size_t arraySize );

public:
    kkRemoteAsyncStackwalk();
    virtual ~kkRemoteAsyncStackwalk();

private:
    static  BOOL    CALLBACK    ReadProcessMemory64( HANDLE hProcess, DWORD64 pBaseAddress, PVOID pBuffer, DWORD nSize, LPDWORD pNumberOfBytesRead );
    static  BOOL    CALLBACK    ReadProcessMemoryWithCache64( HANDLE hProcess, DWORD64 pBaseAddress, PVOID pBuffer, DWORD nSize, LPDWORD pNumberOfBytesRead );
protected:
    DWORD           m_dwProcessId;
    HANDLE          m_hProcess;
    BOOL            m_bIsWow64;

    CRITICAL_SECTION    m_cs;

    union MIX_CONTEXT
    {
        CONTEXT     context;
#if defined(_M_X64)
        WOW64_CONTEXT   contextWow64;
#endif // defined(_M_IA64)
    };

    struct ModuleInfo
    {
        void*           pBuff;
        size_t          size;
        DWORD64         dwAddrStart;
        DWORD64         dwAddrEnd;
        std::wstring    strModuleName;

        ModuleInfo()
        {
            pBuff = NULL;
            size = 0;
            dwAddrStart = 0;
            dwAddrEnd = 0;
        }
    };

    static  ModuleInfo      m_stack;
};

kkRemoteAsyncStackwalk::ModuleInfo      kkRemoteAsyncStackwalk::m_stack;

kkRemoteAsyncStackwalk::kkRemoteAsyncStackwalk()
    : m_dwProcessId(0), m_hProcess(NULL)
{
    ::InitializeCriticalSection( &m_cs );
}

kkRemoteAsyncStackwalk::~kkRemoteAsyncStackwalk()
{
    const bool bRet = detachProcess();
    if ( false == bRet )
    {
        ::OutputDebugStringW( L"detachProcess fail\n" );
    }
    ::DeleteCriticalSection( &m_cs );

    if ( NULL != m_stack.pBuff )
    {
        free( m_stack.pBuff );
        m_stack.pBuff = NULL;
        m_stack.size = 0;
        m_stack.dwAddrStart = 0;
        m_stack.dwAddrEnd = 0;
    }
}

bool
kkRemoteAsyncStackwalk::attachProcess( const DWORD dwProcessId )
{
    detachProcess();

    if ( NULL != m_hProcess )
    {
        return false;
    }

    {
        const DWORD dwDesiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        const BOOL bInheritHandle = FALSE;
        m_hProcess = ::OpenProcess( dwDesiredAccess, bInheritHandle, dwProcessId );
        if ( NULL == m_hProcess )
        {
            return false;
        }
    }

    {
        const BOOL BRet = ::IsWow64Process( m_hProcess, &m_bIsWow64 );
        if ( FALSE == BRet )
        {
            return false;
        }
    }
    this->initDebugHelp();

    return true;
}

bool
kkRemoteAsyncStackwalk::detachProcess( void )
{
    bool result = true;

    this->termDebugHelp();

    if ( NULL != m_hProcess )
    {
        const BOOL BRet = ::CloseHandle( m_hProcess );
        if ( BRet )
        {
            m_bIsWow64 = FALSE;
            m_hProcess = NULL;
            m_dwProcessId = 0;
        }
        else
        {
            result = false;
        }
    }
    else
    {
        m_bIsWow64 = FALSE;
        m_dwProcessId = 0;
    }

    return result;
}

bool
kkRemoteAsyncStackwalk::initDebugHelp(void)
{
    if ( NULL == m_hProcess )
    {
        return false;
    }

    bool result = true;
    ::EnterCriticalSection( &m_cs );
    {
        const BOOL BRet = ::SymInitializeW( m_hProcess, NULL, TRUE );
        if ( FALSE == BRet )
        {
            result = false;
        }
    }
    ::LeaveCriticalSection( &m_cs );

    return result;
}

bool
kkRemoteAsyncStackwalk::termDebugHelp(void)
{
    if ( NULL == m_hProcess )
    {
        return false;
    }

    bool result = true;
    ::EnterCriticalSection( &m_cs );
    {
        const BOOL BRet = ::SymCleanup( m_hProcess );
        if ( FALSE == BRet )
        {
            result = false;
        }
    }
    ::LeaveCriticalSection( &m_cs );

    return true;
}

BOOL
CALLBACK
kkRemoteAsyncStackwalk::ReadProcessMemory64(
    HANDLE hProcess
    , DWORD64 pBaseAddress
    , PVOID pBuffer
    , DWORD nSize
    , LPDWORD pNumberOfBytesRead
)
{
#if MESURE_TIME
    const DWORD timeStart = ::GetTickCount();
#endif // MESURE_TIME

    LPCVOID pBase = reinterpret_cast<LPCVOID>(pBaseAddress);
    SIZE_T  size = nSize;
    SIZE_T  readedSize = 0;
    const BOOL BRet = ::ReadProcessMemory( hProcess, pBase, pBuffer, size, &readedSize );

#if MESURE_TIME
    const DWORD timeEnd = ::GetTickCount();
    s_dwTimeReadMemory += (timeEnd - timeStart);
#endif // MESURE_TIME

    if ( NULL != pNumberOfBytesRead )
    {
        *pNumberOfBytesRead = (DWORD)readedSize;
    }

    return BRet;
}

BOOL
CALLBACK
kkRemoteAsyncStackwalk::ReadProcessMemoryWithCache64(
    HANDLE hProcess
    , DWORD64 pBaseAddress
    , PVOID pBuffer
    , DWORD nSize
    , LPDWORD pNumberOfBytesRead
)
{
    const kkRemoteAsyncStackwalk::ModuleInfo&   rStack = kkRemoteAsyncStackwalk::m_stack;
    if ( NULL != rStack.pBuff )
    {
        if ( rStack.dwAddrStart <= pBaseAddress && (pBaseAddress+nSize) <= rStack.dwAddrEnd )
        {
            memcpy( pBuffer, rStack.pBuff, nSize );

            if ( NULL != pNumberOfBytesRead )
            {
                *pNumberOfBytesRead = nSize;
            }

            return TRUE;
        }
    }

#if MESURE_TIME
    const DWORD timeStart = ::GetTickCount();
#endif // MESURE_TIME

    LPCVOID pBase = reinterpret_cast<LPCVOID>(pBaseAddress);
    SIZE_T  size = nSize;
    SIZE_T  readedSize = 0;
    const BOOL BRet = ::ReadProcessMemory( hProcess, pBase, pBuffer, size, &readedSize );

#if MESURE_TIME
    const DWORD timeEnd = ::GetTickCount();
    s_dwTimeReadMemory += (timeEnd - timeStart);
#endif // MESURE_TIME

    if ( NULL != pNumberOfBytesRead )
    {
        *pNumberOfBytesRead = (DWORD)readedSize;
    }

    return BRet;
}

bool
kkRemoteAsyncStackwalk::getStackTrace( HANDLE hThread, DWORD64 *pStackArray, const size_t arraySize)
{
    if ( NULL == m_hProcess )
    {
        return false;
    }

    LPVOID      pContextRecord = NULL;
#if USE_GETTHREADCONTEXT
    MIX_CONTEXT context;
    ZeroMemory( &context, sizeof(context) );

#if defined(_M_X64)
    if ( this->isWow64Process() )
    {
        //context.contextWow64.ContextFlags = WOW64_CONTEXT_ALL;
        context.contextWow64.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS;
    }
    else
    {
        //context.context.ContextFlags = CONTEXT_ALL;
        context.context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
    }
#endif // defined(_M_X64)
#if defined(_M_IX86)
        //context.context.ContextFlags = CONTEXT_ALL;
        context.context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
#endif
#if defined(_M_IA64)
        //context.context.ContextFlags = CONTEXT_ALL;
        context.context.ContextFlags = CONTEXT_INTEGER;
#endif

    {
#if MESURE_TIME
        const DWORD timeStart = ::GetTickCount();
#endif // MESURE_TIME

#if defined(_M_X64)
        const BOOL BRet =
            (this->isWow64Process())
            ?(::Wow64GetThreadContext( hThread, &context.contextWow64 ))
            :(::GetThreadContext( hThread, &context.context ));
#else
        const BOOL BRet = ::GetThreadContext( hThread, &context.context );
#endif

#if MESURE_TIME
        const DWORD timeEnd = ::GetTickCount();
        s_dwTimeGetThreadContext += (timeEnd - timeStart);
#endif // MESURE_TIME

        if ( FALSE == BRet )
        {
            ::OutputDebugStringW( L"GetThreadContext fail\n" );
        }
        else
        {
            pContextRecord = &context;
        }
    }
#endif // USE_GETTHREADCONTEXT

    {
        const bool bRet = this->captureStack( hThread, &context );
    }

    STACKFRAME64    stackFrame;
    ZeroMemory( &stackFrame, sizeof(stackFrame) );

    DWORD   dwMachineType = 0;
#if USE_GETTHREADCONTEXT
#if defined(_M_X64)
    if ( this->isWow64Process() )
    {
        dwMachineType = IMAGE_FILE_MACHINE_I386;
        stackFrame.AddrPC.Offset = context.contextWow64.Eip;
        stackFrame.AddrFrame.Offset = context.contextWow64.Ebp;
        stackFrame.AddrStack.Offset = context.contextWow64.Esp;
    }
    else
    {
        dwMachineType = IMAGE_FILE_MACHINE_AMD64;
        stackFrame.AddrPC.Offset = context.context.Rip;
        stackFrame.AddrFrame.Offset = context.context.Rbp;
        stackFrame.AddrStack.Offset = context.context.Rsp;
    }
#endif // defined(_M_X64)
#if defined(_M_IX86)
    dwMachineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = context.context.Eip;
    stackFrame.AddrFrame.Offset = context.context.Ebp;
    stackFrame.AddrStack.Offset = context.context.Esp;
#endif // defined(_M_X86)
#if defined(_M_IA64)
    dwMachineType = IMAGE_FILE_MACHINE_IA64;
    stackFrame.AddrPC.Offset = context.StIIP;
    stackFrame.AddrFrame.Offset = context.RsBSP;
    stackFrame.AddrStack.Offset = context.IntSP;
    stackFrame.AddrBStore.Offset = context.RsBSP;
#endif // defined(_M_IA64)
#else // USE_GETTHREADCONTEXT
#if defined(_M_X64)
    dwMachineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = 0;
    stackFrame.AddrFrame.Offset = 0;
    stackFrame.AddrStack.Offset = 0;
#endif // defined(_M_X64)
#if defined(_M_IX86)
    dwMachineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = 0;
    stackFrame.AddrFrame.Offset = 0;
    stackFrame.AddrStack.Offset = 0;
#endif // defined(_M_X86)
#if defined(_M_IA64)
    dwMachineType = IMAGE_FILE_MACHINE_IA64;
    stackFrame.AddrPC.Offset = 0;
    stackFrame.AddrFrame.Offset = 0;
    stackFrame.AddrStack.Offset = 0;
    stackFrame.AddrBStore.Offset = 0;
#endif // defined(_M_IA64)
#endif // USE_GETTHREADCONTEXT

    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrBStore.Mode = AddrModeFlat;

    bool result = true;
    ::EnterCriticalSection( &m_cs );
    {
        __try
        {
            size_t count = 0;
            for ( count = 0; count < arraySize; ++count )
            {
#if MESURE_TIME
                const DWORD timeStart = ::GetTickCount();
#endif // MESURE_TIME

                const BOOL BRet = ::StackWalk64(
                    dwMachineType
                    , m_hProcess
                    , hThread
                    , &stackFrame
                    , pContextRecord
                    , ReadProcessMemoryWithCache64
                    , NULL
                    , NULL
                    , NULL
                    );
#if MESURE_TIME
                const DWORD timeEnd = ::GetTickCount();
                s_dwTimeStackWalk += (timeEnd - timeStart);
#endif // MESURE_TIME
                if ( FALSE == BRet )
                {
                    break;
                }

                pStackArray[count] = stackFrame.AddrPC.Offset;

            }

            if ( 0 == count )
            {
                ::OutputDebugStringW( L"StackWalk64 fail\n" );
                result = false;
            }
        }
        __except( EXCEPTION_CONTINUE_EXECUTION )
        {
        }
    }
    ::LeaveCriticalSection( &m_cs );

    return result;
}

bool
kkRemoteAsyncStackwalk::captureStack( HANDLE hThread, LPVOID pContextRecord )
{
#if defined(_M_IA64)
    const CONTEXT* pContext = (const CONTEXT*)pContextRecord;
    TEB* pRemoteTEB = pContext->IntTeb;
#else // defined(_M_IA64)

#if defined(_M_X64)
    bool result = true;
    typedef ULONG   KPRIORITY;
    struct CLIENT_ID
    {
        HANDLE      UniqueProcessId;
        HANDLE      UniqueThreadId;
    };
    struct THREAD_BASIC_INFORMATION
    {
        NTSTATUS    ExitStatus;
        PVOID       TebBaseAddress;
        CLIENT_ID   ClientId;
        KAFFINITY   AffinityMask;
        KPRIORITY   Priority;
        KPRIORITY   BasePriority;
    };
    THREAD_BASIC_INFORMATION basicInfo;
    const size_t ThreadBasicInformation = 0;
    ULONG   returnLength = 0;
    HMODULE hModule = ::GetModuleHandleW( L"ntdll.dll" );
    if ( NULL != hModule )
    {
        typedef NTSTATUS (WINAPI * PFN_NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength );
        PFN_NtQueryInformationThread    pfnNtQueryInformationThread = NULL;
        pfnNtQueryInformationThread = (PFN_NtQueryInformationThread)::GetProcAddress( hModule, "NtQueryInformationThread" );
        if ( NULL != pfnNtQueryInformationThread )
        {
            const NTSTATUS status = pfnNtQueryInformationThread( hThread, (THREADINFOCLASS)ThreadBasicInformation, &basicInfo, sizeof(basicInfo), &returnLength );
            //if ( !NT_SUCCESS(status) )
            if ( status < 0 )
            {
                result = false;
            }
            else
            {
                //wchar_t temp[256];
                //::wsprintfW( temp, L"pTEB=%p from ThreadBasicInformation\n", basicInfo.TebBaseAddress );
                //::OutputDebugStringW( temp );

                NT_TIB      tib;
                ZeroMemory( &tib, sizeof(tib) );
                DWORD64 dwTEBremote = reinterpret_cast<DWORD64>(basicInfo.TebBaseAddress);
                const BOOL BRet = kkRemoteAsyncStackwalk::ReadProcessMemory64( this->m_hProcess, dwTEBremote, &tib, sizeof(tib), NULL );
                if ( FALSE == BRet )
                {
                    const DWORD dwErr = ::GetLastError();
                    ::DebugBreak();
                }
                else
                {
                    if ( reinterpret_cast<DWORD64>(tib.Self) == dwTEBremote )
                    {
                        size_t nSize = (LPBYTE)tib.StackBase - (LPBYTE)tib.StackLimit;

                        if ( NULL != m_stack.pBuff )
                        {
                            if ( m_stack.size != nSize )
                            {
                                free( m_stack.pBuff );
                                m_stack.size = 0;
                                m_stack.pBuff = NULL;
                            }
                        }

                        {
                            m_stack.pBuff = malloc( nSize );
                            if ( NULL != m_stack.pBuff )
                            {
                                m_stack.size = nSize;
                                m_stack.dwAddrStart = reinterpret_cast<DWORD64>(tib.StackLimit);
                                m_stack.dwAddrEnd = reinterpret_cast<DWORD64>(tib.StackBase);

                                const BOOL BRetCapture = kkRemoteAsyncStackwalk::ReadProcessMemory64( this->m_hProcess, m_stack.dwAddrStart, m_stack.pBuff, m_stack.size, NULL );
                                if ( FALSE == BRetCapture )
                                {
                                    const DWORD dwErr = ::GetLastError();
                                    ::DebugBreak();
                                }
                                else
                                {

                                }
                            }
                        }
                    }
                }

            }
        }
    }
#endif // defined(_M_X64)

#if defined(_M_IX86)
    LDT_ENTRY   ldtEntry;
    ZeroMemory( &ldtEntry, sizeof(ldtEntry) );

    const CONTEXT* pContext = (const CONTEXT*)pContextRecord;
    const DWORD dwSelector = pContext->SegFs;

    bool result = true;
    const BOOL BRet = ::GetThreadSelectorEntry( hThread, dwSelector, &ldtEntry );
    if ( FALSE == BRet )
    {
        result = false;
    }
    else
    {
        DWORD64 dwTEBremote = 
            ldtEntry.BaseLow
            | (ldtEntry.HighWord.Bytes.BaseMid << 16)
            | (ldtEntry.HighWord.Bytes.BaseHi  << 24)
            ;

        NT_TIB      tib;
        ZeroMemory( &tib, sizeof(tib) );
        const BOOL BRet = kkRemoteAsyncStackwalk::ReadProcessMemory64( this->m_hProcess, dwTEBremote, &tib, sizeof(tib), NULL );
        if ( FALSE == BRet )
        {
            const DWORD dwErr = ::GetLastError();
            ::DebugBreak();
        }
        else
        {
            if ( reinterpret_cast<DWORD64>(tib.Self) == dwTEBremote )
            {
                size_t nSize = (LPBYTE)tib.StackBase - (LPBYTE)tib.StackLimit;

                if ( NULL != m_stack.pBuff )
                {
                    if ( m_stack.size != nSize )
                    {
                        free( m_stack.pBuff );
                        m_stack.size = 0;
                        m_stack.pBuff = NULL;
                    }
                }

                {
                    m_stack.pBuff = malloc( nSize );
                    if ( NULL != m_stack.pBuff )
                    {
                        m_stack.size = nSize;
                        m_stack.dwAddrStart = reinterpret_cast<DWORD64>(tib.StackLimit);
                        m_stack.dwAddrEnd = reinterpret_cast<DWORD64>(tib.StackBase);

                        const BOOL BRetCapture = kkRemoteAsyncStackwalk::ReadProcessMemory64( this->m_hProcess, m_stack.dwAddrStart, m_stack.pBuff, m_stack.size, NULL );
                        if ( FALSE == BRetCapture )
                        {
                            const DWORD dwErr = ::GetLastError();
                            ::DebugBreak();
                        }
                        else
                        {

                        }
                    }
                }
            }
        }
    }
#endif // defined(_M_IX86)

    return result;
#endif // defined(_M_IA64)
}

static volatile
bool        s_bNeedTerminate = false;

static
BOOL WINAPI
ConsoleCtrlHandler( DWORD dwCtrlType )
{
    switch( dwCtrlType )
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        s_bNeedTerminate = true;
        break;
    }

    return TRUE;
}


int _tmain(int argc, _TCHAR* argv[])
{
#if defined(_DEBUG)
    {
        const int value = ::_CrtSetDbgFlag( 0 );
        ::_CrtSetDbgFlag( value | _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
    }
#endif // defined(_DEBUG)
    {
        ::SetConsoleCtrlHandler( ConsoleCtrlHandler, TRUE );
    }

    DWORD   dwProcessId = 0;

    for ( int index = 1; index < argc; ++index )
    {
        if ( NULL == argv[index] )
        {
            continue;
        }

        if ( 0 == _tcsncmp( argv[index], _T("--pid="), _tcslen(_T("--pid="))))
        {
            const long lResult = _tcstol( &argv[index][_tcslen(_T("--pid="))], NULL, 10 ); 
            dwProcessId = static_cast<DWORD>(lResult);
        }
    }

    if ( 0 == dwProcessId )
    {
        STARTUPINFOW    startupInfo;
        ZeroMemory( &startupInfo, sizeof(startupInfo) );
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION     processInfo;
        ZeroMemory( &processInfo, sizeof(processInfo) );

        wchar_t cmdLine[512];
        cmdLine[0] = '\0';
        {
            LPWSTR strCmdLine = ::GetCommandLineW();
            if ( NULL != strCmdLine )
            {
                const wchar_t* p = ::wcsstr( strCmdLine, argv[1] );
                p += ::wcslen( argv[1] );
                ::wcscpy_s( cmdLine, sizeof(cmdLine)/sizeof(cmdLine[0]), p );
            }
        }

        const BOOL BRet = ::CreateProcessW( argv[1], cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo );
        if ( FALSE == BRet )
        {
            const DWORD dwErr = ::GetLastError();
            ::OutputDebugStringW( L"CreateProcess failed.\n" );
        }
        else
        {
            ::CloseHandle( processInfo.hThread );
            ::CloseHandle( processInfo.hProcess );
            dwProcessId = processInfo.dwProcessId;
        }
    }

    if ( 0 == dwProcessId )
    {
        return false;
    }


    kkRemoteAsyncStackwalk      remote;

    {
        remote.attachProcess( dwProcessId );
    }

    //if ( remote.isWow64Process() )
    {
        for ( ; ; )
        {
            const DWORD dwFlags = TH32CS_SNAPMODULE;
            HANDLE hSnapshot = ::CreateToolhelp32Snapshot( dwFlags, dwProcessId );

            if ( INVALID_HANDLE_VALUE == hSnapshot )
            {
                const DWORD dwErr = ::GetLastError();
                if (
                    ERROR_PARTIAL_COPY == dwErr
                    || ERROR_BAD_LENGTH == dwErr
                )
                {
                    ::OutputDebugStringW( L"." );
                    continue;
                }
                else
                {
                    break;
                }
            }
            else
            {
                const BOOL BRet = ::CloseHandle( hSnapshot );
                if ( FALSE == BRet )
                {

                }
                else
                {
                    hSnapshot = INVALID_HANDLE_VALUE;
                }
                break;
            }
        }
        ::OutputDebugStringW( L"\n" );
    }

    ::Sleep( 10*1000 );

    {
        const DWORD dwFlags = TH32CS_SNAPMODULE;
        HANDLE hSnapshot = ::CreateToolhelp32Snapshot( dwFlags, dwProcessId );

        if ( INVALID_HANDLE_VALUE == hSnapshot )
        {
            const DWORD dwErr = ::GetLastError();
            if ( ERROR_PARTIAL_COPY == dwErr )
            {
                ::OutputDebugStringW( L"Target process is 64bit\n" );
            }
            return 1;
        }
        else
        {
            MODULEENTRY32W  moduleEntry;
            moduleEntry.dwSize = sizeof(MODULEENTRY32W);

            const BOOL BRet = ::Module32FirstW( hSnapshot, &moduleEntry );
            if ( BRet )
            {
                do
                {
                    {
                        wchar_t     temp[256];
                        ::wsprintfW( temp, L"%p %p %s\n", moduleEntry.modBaseAddr, moduleEntry.modBaseSize, moduleEntry.szExePath );
                        ::OutputDebugStringW( temp );
                    }

                } while ( ::Module32NextW( hSnapshot, &moduleEntry ) );
            }
            else
            {
                const DWORD dwErr = ::GetLastError();
                ::OutputDebugStringW( L"" );
            }
        }

        if ( INVALID_HANDLE_VALUE != hSnapshot )
        {
            const BOOL BRet = ::CloseHandle( hSnapshot );
            if ( BRet )
            {
                hSnapshot = NULL;
            }
        }
    }
    {
        ::OutputDebugStringW( L"\n" );
    }
#if 1//defined(_M_X64)
    {
        const DWORD dwFlags = TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32;
        HANDLE hSnapshot = ::CreateToolhelp32Snapshot( dwFlags, dwProcessId );

        if ( INVALID_HANDLE_VALUE != hSnapshot )
        {
            MODULEENTRY32W  moduleEntry;
            moduleEntry.dwSize = sizeof(MODULEENTRY32W);

            const BOOL BRet = ::Module32FirstW( hSnapshot, &moduleEntry );
            if ( BRet )
            {
                do
                {
                    {
                        wchar_t     temp[256];
                        ::wsprintfW( temp, L"%p %p %s\n", moduleEntry.modBaseAddr, moduleEntry.modBaseSize, moduleEntry.szExePath );
                        ::OutputDebugStringW( temp );
                    }
                } while ( ::Module32NextW( hSnapshot, &moduleEntry ) );
            }
            else
            {
                const DWORD dwErr = ::GetLastError();
                ::OutputDebugStringW( L"" );
            }
        }

        if ( INVALID_HANDLE_VALUE != hSnapshot )
        {
            const BOOL BRet = ::CloseHandle( hSnapshot );
            if ( BRet )
            {
                hSnapshot = NULL;
            }
        }
    }
#endif // defined(_M_X64)

    DWORD64     stackArray[128];
    while( false == s_bNeedTerminate )
    {
        const DWORD dwFlags = TH32CS_SNAPTHREAD;
        HANDLE hSnapshot = ::CreateToolhelp32Snapshot( dwFlags, 0 );
        if ( INVALID_HANDLE_VALUE != hSnapshot )
        {
            THREADENTRY32   threadEntry;
            threadEntry.dwSize = sizeof(threadEntry);

            const BOOL BRetFirst = ::Thread32First( hSnapshot, &threadEntry );
            if ( BRetFirst )
            {
                //printf( "\n" );
                do
                {
                    if ( dwProcessId != threadEntry.th32OwnerProcessID )
                    {
                        continue;
                    }
                    //printf( "tid=%u\n", threadEntry.th32ThreadID );

                    const DWORD dwDesiredAccess = THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
                    HANDLE hThread = ::OpenThread( dwDesiredAccess, FALSE, threadEntry.th32ThreadID );
                    if ( NULL == hThread )
                    {
                        const DWORD dwErr = ::GetLastError();
                        ::OutputDebugStringW( L"OpenThread fail.\n" );
                    }
                    else
                    {
#if MESURE_TIME
                        const DWORD timeStart = ::GetTickCount();
#endif // MESURE_TIME
                        remote.getStackTrace( hThread, stackArray, sizeof(stackArray)/sizeof(stackArray[0]) );
#if MESURE_TIME
                        const DWORD timeEnd = ::GetTickCount();
                        s_dwTimeGetStack += (timeEnd - timeStart);
#endif // MESURE_TIME
                    }

                    if ( NULL != hThread )
                    {
                        const BOOL BRet = ::CloseHandle( hThread );
                        if ( BRet )
                        {
                            hThread = NULL;
                        }
                    }
                } while( ::Thread32Next( hSnapshot, &threadEntry ) );
            }
        }

        if ( INVALID_HANDLE_VALUE != hSnapshot )
        {
            const BOOL BRet = ::CloseHandle( hSnapshot );
            if ( BRet )
            {
                hSnapshot = INVALID_HANDLE_VALUE;
            }
        }

#if MESURE_TIME
        printf( "%u %u %u %u\n"
            , s_dwTimeGetStack
            , s_dwTimeGetThreadContext
            , s_dwTimeStackWalk
            , s_dwTimeReadMemory
            );

        s_dwTimeGetStack = 0;
        s_dwTimeGetThreadContext = 0;
        s_dwTimeStackWalk = 0;
        s_dwTimeReadMemory = 0;
#endif // MESURE_TIME

        ::Sleep( 1*100 );
    }

	return 0;
}

