/*
 * This software is licensed under the NoCEG Non-Commercial Copyleft License.
 *
 * Copyright (C) 2025 iArtorias <iartorias.re@gmail.com>
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

#include <Windows.h>
#include <thread>
#include <array>

// Enumeration representing possible error states in the application.
enum class Error
{
    Success, // No error occurred.
    GetModuleNameFailed, // Failed to retrieve the current module's file name.
    CreateProcessFailed, // Failed to create a new process.
    JsonReadFailed, // Failed to read JSON data.
    JsonParseFailed, // Failed to parse JSON data.
    JsonWriteFailed, // Failed to write JSON data.
    MutexCreateFailed, // Failed to create or acquire a mutex.
    CEGVersionNotFound, // CEG version field not found.
    CEGInitFunctionNotFound, // CEG init function not found inside JSON.
    CEGRegisterThreadFunctionNotFound // CEG register thread function not found inside JSON.
};

// The handle manager.
class HandleManager
{
private:

    // The managed handle initialized to an invalid state.
    HANDLE m_Handle { INVALID_HANDLE_VALUE };

public:

    explicit HandleManager( HANDLE handle ) noexcept : m_Handle { handle }
    {}

    ~HandleManager() noexcept
    {
        if (m_Handle != INVALID_HANDLE_VALUE && m_Handle != nullptr)
            CloseHandle( m_Handle );
    }

    HandleManager( const HandleManager & ) = delete;
    HandleManager & operator=( const HandleManager & ) = delete;
};


// Process restart utility.
class ProcessManager
{
private:

    // A custom mutex.
    static constexpr const char * CEG_RESTART_MUTEX = "Global\\NoCEG";

public:
    
    /**
     * @brief Restarts the current process safely using a global mutex.
     * 
     * @return 'std::expected<void, Error>' Either success or error.
     */
    [[nodiscard]] static std::expected<void, Error> SelfRestart() noexcept
    {
        // Create or open a named mutex to prevent multiple simultaneous restarts.
        HANDLE mtx = CreateMutexA( nullptr, FALSE, CEG_RESTART_MUTEX );
        if (!mtx)
            return std::unexpected { Error::MutexCreateFailed };

        HandleManager mutex_handle( mtx );

        auto const res = WaitForSingleObject( mtx, 0 );

        // If the mutex couldn't be acquired, return an error.
        if (res != WAIT_OBJECT_0)
            return std::unexpected { Error::MutexCreateFailed };
        
        // Successfully acquired the mutex, now get the current executable path.
        std::array<char, MAX_PATH> path {};
        if (GetModuleFileNameA( nullptr, path.data(), MAX_PATH ) == 0)
        {
            ReleaseMutex( mtx );
            return std::unexpected { Error::GetModuleNameFailed };
        }

        STARTUPINFOA si {};
        PROCESS_INFORMATION pi {};
        si.cb = sizeof( si );

        if (!CreateProcessA(
            path.data(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
            &si, &pi ))
        {
            ReleaseMutex( mtx );
            return std::unexpected { Error::CreateProcessFailed };
        }

        HandleManager process_handle { pi.hProcess };
        HandleManager thread_handle { pi.hThread };

        // Release the mutex after successful process creation.
        ReleaseMutex( mtx );

        return {};
    }


    /**
     * @brief Waits for the CEG mutex if it exists.
     * 
     * Used to synchronize with a potentially restarted process.
     */
    static void GetCEGMutex() noexcept
    {
        HANDLE mtx = OpenMutexA( SYNCHRONIZE, FALSE, CEG_RESTART_MUTEX );
        if (mtx)
        {
            WaitForSingleObject( mtx, INFINITE );

            ReleaseMutex( mtx );
            CloseHandle( mtx );
        }
    }
};