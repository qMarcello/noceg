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

#include "pch.h"

#include <reader.h>
#include <process.h>
#include <memory.h>
#include <app.h>
#include <entry.h>
#include <proxy.h>
#include <exports.h>
#include <handler.h>

// Optional dedicated thread for initializing and running the whole logic.
// Disabled for now.
/*DWORD WINAPI NoCEGThread(void *) noexcept
{
    auto state = std::make_unique<ApplicationManager>();

    auto & processor = state->GetEntryProcessorManager();
    if (auto res = processor.Initialize(); !res)
        return static_cast<DWORD>(res.error());

    return static_cast<DWORD>(Error::Success);
}*/

BOOL APIENTRY DllMain( 
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
) noexcept
{
    static std::once_flag once;

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            DisableThreadLibraryCalls( hModule );

            Log::Logger::Configure( "noceg.log", true );
            LOG_INFO( "CEG resolver by iArtorias (https://github.com/iArtorias)." );

            // Always perform once attached.
            ProcessManager::GetCEGMutex();
            SteamAPIWrapper::Initialize();

            std::call_once( once, [hModule]
            {
                std::array<char, MAX_PATH> json_path {};
                if (GetModuleFileNameA( nullptr, json_path.data(), MAX_PATH ) == 0)
                {
                    LOG_ERROR( "Could not obtain the full module path. Last error is '0x{:08X}'.", GetLastError() );
                    std::exit( 1 );
                }
                   
                auto state = std::make_unique<ApplicationManager>( fs::path( json_path.data() ).parent_path() / "noceg.json" );

                auto & processor = state->GetEntryProcessorManager();
                if (auto res = processor.Initialize(); !res)
                {
                    LOG_ERROR( "Failed to initialize entry '0x{:08X}'.", static_cast<int>(res.error()) );
                    std::exit( 1 );
                }

                /*
                * // Optional CEG worker thread initialization. Disabled for now.
                HandleManager handle {CreateThread(nullptr, 0, NoCEGThread, nullptr, 0, nullptr)};
                */
            } );

            break;
        }

        case DLL_PROCESS_DETACH:
        {
            SteamAPIWrapper::Shutdown();
            break;
        }
    }

    return TRUE;
}