/*
 * This software is licensed under the NoCEG Non-Commercial Copyleft License.
 *
 * Copyright (C) 2026 iArtorias <iartorias.re@gmail.com>
 *
 * You may use, copy, modify, and distribute this software non-commercially only.
 * If you distribute binaries or run it as a service, you must also provide
 * the full source code under the same license.
 *
 * This software is provided "as is", without warranty of any kind.
 *
 * Full license text available in LICENSE
 */

#pragma once

// These are the fake values.
namespace FakeData
{
    inline constexpr WORD DAY_OF_WEEK = 7;
    inline constexpr LONG TIMEZONE_BIAS = -20;
    inline constexpr std::array<char, 2> COMPUTER_NAME = { '\x08', '\0' };
    inline constexpr DWORD COMPUTER_NAME_LENGTH = 1;
}


// WinAPI hooks manager.
class HookManager
{
private:

    inline static SafetyHookInline GetSystemTime_ptr {};
    inline static SafetyHookInline FileTimeToSystemTime_ptr {};
    inline static SafetyHookInline GetComputerNameA_ptr {};
    inline static SafetyHookInline GetTimeZoneInformation_ptr {};

    // 'GetSystemTimeHook' hook.
    static void WINAPI GetSystemTimeHook(
        _Out_ LPSYSTEMTIME lpSystemTime
    ) noexcept
    {
        if (!lpSystemTime) [[unlikely]]
            return;

        GetSystemTime_ptr.stdcall<void>( lpSystemTime );

        lpSystemTime->wDayOfWeek = FakeData::DAY_OF_WEEK;
    }

    // 'FileTimeToSystemTime' hook.
    static BOOL WINAPI FileTimeToSystemTimeHook(
        _In_ CONST FILETIME * lpFileTime,
        _Out_ LPSYSTEMTIME lpSystemTime
    ) noexcept
    {
        if (!lpFileTime || !lpSystemTime) [[unlikely]]
        {
            ::SetLastError( ERROR_INVALID_PARAMETER );
            return FALSE;
        }

        const BOOL result = FileTimeToSystemTime_ptr.stdcall<BOOL>(
            lpFileTime, lpSystemTime );

        if (result) [[likely]]
            lpSystemTime->wDayOfWeek = FakeData::DAY_OF_WEEK;

        return result;
    }


    // 'GetComputerNameA' hook.
    static BOOL WINAPI GetComputerNameAHook(
        _Out_writes_to_opt_( *nSize, *nSize + 1 ) LPSTR lpBuffer,
        _Inout_ LPDWORD nSize
    ) noexcept
    {
        if (!nSize) [[unlikely]]
        {
            ::SetLastError( ERROR_INVALID_PARAMETER );
            return FALSE;
        }

        if (!lpBuffer && *nSize > 0) [[unlikely]]
        {
            ::SetLastError( ERROR_INVALID_PARAMETER );
            return FALSE;
        }

        if (*nSize < FakeData::COMPUTER_NAME_LENGTH + 1) [[unlikely]]
        {
            *nSize = FakeData::COMPUTER_NAME_LENGTH + 1;
            ::SetLastError( ERROR_BUFFER_OVERFLOW );

            return FALSE;
        }

        if (lpBuffer && *nSize > 1) [[likely]]
        {
            std::span<char> buffer_span( lpBuffer, *nSize );
            std::ranges::copy( FakeData::COMPUTER_NAME, buffer_span.begin() );

            *nSize = FakeData::COMPUTER_NAME_LENGTH;
        }

        return TRUE;
    }


    // 'GetTimeZoneInformation' hook.
    static DWORD WINAPI GetTimeZoneInformationHook(
        _Out_ LPTIME_ZONE_INFORMATION lpTimeZoneInformation
    ) noexcept
    {
        if (!lpTimeZoneInformation) [[unlikely]]
            return TIME_ZONE_ID_INVALID;

        const DWORD result = GetTimeZoneInformation_ptr.stdcall<DWORD>(
            lpTimeZoneInformation );

        if (result != TIME_ZONE_ID_INVALID) [[likely]]
            lpTimeZoneInformation->Bias = FakeData::TIMEZONE_BIAS;

        return result;
    }

public:

    ~HookManager()
    {
        UninstallHooks();
    }

    void InstallHooks() noexcept
    {
        GetSystemTime_ptr = safetyhook::create_inline(
            reinterpret_cast<void *>(&GetSystemTime),
            reinterpret_cast<void *>(&GetSystemTimeHook) );

        FileTimeToSystemTime_ptr = safetyhook::create_inline(
            reinterpret_cast<void *>(&FileTimeToSystemTime),
            reinterpret_cast<void *>(&FileTimeToSystemTimeHook) );

        GetComputerNameA_ptr = safetyhook::create_inline(
            reinterpret_cast<void *>(&GetComputerNameA),
            reinterpret_cast<void *>(&GetComputerNameAHook) );

        GetTimeZoneInformation_ptr = safetyhook::create_inline(
            reinterpret_cast<void *>(&GetTimeZoneInformation),
            reinterpret_cast<void *>(&GetTimeZoneInformationHook) );
    }


    void UninstallHooks() noexcept
    {
        GetSystemTime_ptr = {};
        FileTimeToSystemTime_ptr = {};
        GetComputerNameA_ptr = {};
        GetTimeZoneInformation_ptr = {};
    }
};

inline HookManager HookMgr;