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

#include "app.h"

// Manager responsible for processing entries related to CEG protected functions.
class EntryProcessorManager
{
private:

    // Custom exception code.
    std::uint32_t m_CustomExceptionCode { 0xDEADDEAD };

    // A unique pointer to the main application manager.
    std::unique_ptr<ApplicationManager> m_AppManager;

public:

    explicit EntryProcessorManager( ApplicationManager * app )
        : m_AppManager( app )
    {}
    

    /**
    * @brief Main loop to process the current JSON entry containing CEG function info.
    *
    * Iterates over function entries in the 'ConstantOrStolen' array of the loaded JSON.
    * Applies breakpoints and raises custom exception to trigger further handling.
    */
    void ProcessEntry()
    {
        auto & config = m_AppManager->GetJSON();
        const auto & json = config.ReadData();

        // Check if 'ConstantOrStolen' key exists.
        if (!json.contains( "ConstantOrStolen" ) || !json["ConstantOrStolen"].is_array())
        {
            LOG_WARNING( "'ConstantOrStolen' key missing or not an array." );
            return;
        }

        auto & bp = m_AppManager->GetBreakpointManager();

        if (json.contains( "BreakpointType" ) && json["BreakpointType"].is_number())
        {
            if (json["BreakpointType"].get<std::int32_t>() == 2) // '2' is 'Hardware'.
                bp.SetBreakpointType( 2 );
        }

        const auto & constant_or_stolen_funcs = json["ConstantOrStolen"];

        for (std::size_t i = m_AppManager->GetCurrentIndex(); i < constant_or_stolen_funcs.size(); ++i)
        {
            const auto & entry = constant_or_stolen_funcs[i];

            // Check if entry is valid and has at least one key value pair.
            if (entry.empty() || !entry.is_object())
            {
                LOG_WARNING( "Skipping invalid entry at index '{}'.", i );
                continue;
            }

            const auto & data = entry.begin().value();

            // Check if data is an object.
            if (!data.is_object())
            {
                LOG_WARNING( "Skipping entry at index '{}', data is not an object.", i );
                continue;
            }

            // Safe check for 'Value' field.
            if (!data.contains( "Value" ) || !data["Value"].is_string())
            {
                LOG_WARNING( "Skipping entry at index '{}', value field missing or invalid.", i );
                continue;
            }

            // Only handle entries where the function hasn't been processed.
            if (data["Value"].get<std::string>() == "0x00000000")
            {
                // Save the current index for resuming or tracking progress.
                m_AppManager->SetCurrentIndex( i );

                try
                {
                    // Check if the function address is valid.
                    const auto func_key = entry.begin().key();
                    if (func_key.empty())
                    {
                        LOG_WARNING( "Entry at index '{}' has empty key.", i );
                        continue;
                    }

                    if (!data.contains( "BP" ) || !data["BP"].is_string())
                    {
                        LOG_WARNING( "'BP' field missing or invalid at index '{}'.", i );
                        continue;
                    }

                    if (!data.contains( "EIP" ) || !data["EIP"].is_string())
                    {
                        LOG_WARNING( "'EIP' field missing or invalid at index '{}'.", i );
                        continue;
                    }

                    if (!data.contains( "Type" ) || !data["Type"].is_number_integer())
                    {
                        LOG_WARNING( "'Type' field missing or invalid at index '{}'.", i );
                        continue;
                    }

                    // Extract the required addresses from the JSON fields.
                    const auto func_addr = static_cast<std::uintptr_t>(std::stoull( func_key, nullptr, 16 ));
                    const auto bp_addr = static_cast<std::uintptr_t>(std::stoull( data["BP"].get<std::string>(), nullptr, 16 ));
                    const auto eip_addr = static_cast<std::uintptr_t>(std::stoull( data["EIP"].get<std::string>(), nullptr, 16 ));

                    // Validate addresses are not zero.
                    if (func_addr == 0 || bp_addr == 0 || eip_addr == 0)
                    {
                        LOG_WARNING( "One or more addresses are zero at index '{}'.", i );
                        continue;
                    }

                    m_AppManager->SetTargetAddress( m_AppManager->CalculateRealAddress( func_addr ) );
                    m_AppManager->SetEipAddress( m_AppManager->CalculateRealAddress( eip_addr ) );

                    bp.SetBreakpoint( m_AppManager->CalculateRealAddress( bp_addr ) );

                    const auto type = data["Type"].get<int>();

                    // Handle various CEG functions.
                    // '1' - CEG constant functions.
                    // '2' - Older CEG stolen/masked functions.
                    // '3', '4' - CEG stolen/masked functions.
                    switch (type)
                    {
                        case 2:
                        {
                            m_AppManager->SetExceptionHandler( CEGExceptionHandler );
                            RaiseException( m_CustomExceptionCode, 0, 0, nullptr );
                            break;
                        }

                        case 1:
                        case 3:
                        case 4:
                        {
                            // Attempt to call the CEG register thread function before proceeding with the exception.
                            const auto ceg_registerthread_addr = m_AppManager->GetRegisterThreadAddress();
                            if (ceg_registerthread_addr)
                            {
                                using CEG_RegisterThread_t = bool(*)();
                                const auto register_thread = reinterpret_cast<CEG_RegisterThread_t>(ceg_registerthread_addr);
                                register_thread();
                            }

                            RaiseException( m_CustomExceptionCode, 0, 0, nullptr );
                            break;
                        }
                    }
                }
                catch (const std::invalid_argument & e)
                {
                    LOG_ERROR( "Failed to parse address at index '{}' ('{}').", i, e.what() );
                    continue;
                }
                catch (const std::out_of_range & e)
                {
                    LOG_ERROR( "Address out of range at index '{}' ('{}').", i, e.what() );
                    continue;
                }
                catch (const nlohmann::json::exception & e)
                {
                    LOG_ERROR( "JSON error at index '{}' ('{}').", i, e.what() );
                    continue;
                }
                catch (const std::exception & e)
                {
                    LOG_ERROR( "Unexpected error at index '{}' ('{}').", i, e.what() );
                    continue;
                }

                continue;
            }
        }

        MessageBoxA( nullptr, "Successfully finished the task!", "NoCEG", MB_OK | MB_ICONINFORMATION );
        ExitProcess( 1 );
    }


    /**
    * @brief Initializes the necessary state and begins entry processing.
    *
    * Loads JSON configuration, extracts function pointers, sets up exception handler,
    * and begins processing entries if core CEG function addresses were found.
    *
    * @return 'std::expected<void, Error>' Either success or error.
    */
    [[nodiscard]] std::expected<void, Error> Initialize()
    {
        auto & config = m_AppManager->GetJSON();

        if (auto res = config.LoadJSON(); !res)
        {
            LOG_ERROR( "Failed to parse 'noceg.json' ('{}').", static_cast<int>(res.error()) );
            return res;
        }

        const auto & json = config.ReadData();

        std::string module_name {};

        // Safe check for 'ModuleName' field.
        if (json.contains( "ModuleName" ) && json["ModuleName"].is_string())
            module_name = json["ModuleName"].get<std::string>();

        if (module_name.ends_with( ".dll" ))
            m_AppManager->SetDefaultImageBase( 0x10000000 );

        m_AppManager->SetTargetImageBase( module_name );

        // Safe check for 'Init' field.
        if (!json.contains( "Init" ) || !json["Init"].is_string())
        {
            return std::unexpected { Error::CEGInitFunctionNotFound };
        }

        const auto ceg_init_addr = static_cast<std::uintptr_t>(std::stoull( json["Init"].get<std::string>(), nullptr, 16 ));

        // Safe check for 'RegisterThread' field.
        if (!json.contains( "RegisterThread" ) || !json["RegisterThread"].is_string())
        {
            return std::unexpected { Error::CEGRegisterThreadFunctionNotFound };
        }

        const auto ceg_registerthread_addr = static_cast<std::uintptr_t>(std::stoull( json["RegisterThread"].get<std::string>(), nullptr, 16 ));

        m_AppManager->SetRegisterThreadAddress( m_AppManager->CalculateRealAddress( ceg_registerthread_addr ) );
        m_AppManager->SetExceptionHandler( CEGExceptionHandler );

        using CEG_Init_t = bool(*)();
        const auto ceg_init = reinterpret_cast<CEG_Init_t>(m_AppManager->CalculateRealAddress( ceg_init_addr ));

        // If the CEG init function is valid and returns true, begin processing.
        if (ceg_init && ceg_init())
        {
            /*
            const auto ceg_version = json["Version"].get<std::uint32_t>();

            // Apply the slight delay for the newer CEG version.
            if (ceg_version > 1)
               Sleep( 100 );
            */

            ProcessEntry();
        }

        return {};
    }
};
