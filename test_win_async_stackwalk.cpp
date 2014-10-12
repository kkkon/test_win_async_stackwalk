// test_async_stackwalk.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

#include <dbghelp.h>
#pragma comment(lib,"dbghelp.lib")
#include <tlhelp32.h>

class kkRemoteAsyncStackwalk
{
public:
    bool    attachProcess( const DWORD dwProcessId );
    bool    detachProcess( void );

    bool    initDebugHelp();
    bool    termDebugHelp();
public:
    kkRemoteAsyncStackwalk();
    virtual ~kkRemoteAsyncStackwalk();

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



int _tmain(int argc, _TCHAR* argv[])
{
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

    kkRemoteAsyncStackwalk      remote;

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
            const DWORD dwRet = ::GetLastError();
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

    {
        remote.attachProcess( dwProcessId );
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




	return 0;
}

