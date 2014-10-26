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


#define USE_GETTHREADCONTEXT 0
#define MESURE_TIME 1

#if MESURE_TIME
static DWORD    s_dwTimeReadMemory = 0;
static DWORD    s_dwTimeGetThreadContext = 0;
static DWORD    s_dwTimeStackWalk = 0;
static DWORD    s_dwTimeGetStack = 0;
#endif // MESURE_TIME


class kkRemoteAsyncStackwalk
{
public:
    bool    attachProcess( const DWORD dwProcessId );
    bool    detachProcess( void );
    bool    isWow64Process( void ) const { return (m_bIsWow64)?(true):(false); }

    bool    initDebugHelp();
    bool    termDebugHelp();

    bool    getStackTrace( HANDLE hThread, DWORD64* pStackArray, const size_t arraySize );

public:
    kkRemoteAsyncStackwalk();
    virtual ~kkRemoteAsyncStackwalk();

private:
    static  BOOL    CALLBACK    ReadProcessMemory64( HANDLE hProcess, DWORD64 pBaseAddress, PVOID pBuffer, DWORD nSize, LPDWORD pNumberOfBytesRead );
protected:
    DWORD           m_dwProcessId;
    HANDLE          m_hProcess;
    BOOL            m_bIsWow64;

    CRITICAL_SECTION    m_cs;
};

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
    const BOOL BRet = ::ReadProcessMemory( hProcess, pBase, pBuffer, nSize, pNumberOfBytesRead );

#if MESURE_TIME
    const DWORD timeEnd = ::GetTickCount();
    s_dwTimeReadMemory += (timeEnd - timeStart);
#endif // MESURE_TIME

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
    CONTEXT     context;
    ZeroMemory( &context, sizeof(context) );
    //context.ContextFlags = CONTEXT_ALL;
    context.ContextFlags = CONTEXT_INTEGER;
    {
#if MESURE_TIME
        const DWORD timeStart = ::GetTickCount();
#endif // MESURE_TIME

        const BOOL BRet = ::GetThreadContext( hThread, &context );

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



    STACKFRAME64    stackFrame;
    ZeroMemory( &stackFrame, sizeof(stackFrame) );

    DWORD   dwMachineType = 0;
#if USE_GETTHREADCONTEXT
#if defined(_M_X64)
    dwMachineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = context.Rip;
    stackFrame.AddrFrame.Offset = context.Rbp;
    stackFrame.AddrStack.Offset = context.Rsp;
#endif // defined(_M_X64)
#if defined(_M_IX86)
    dwMachineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = context.Eip;
    stackFrame.AddrFrame.Offset = context.Ebp;
    stackFrame.AddrStack.Offset = context.Esp;
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
                    , ReadProcessMemory64
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

    if ( remote.isWow64Process() )
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
#if defined(_M_X64)
    {
        const DWORD dwFlags = TH32CS_SNAPMODULE32;
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

