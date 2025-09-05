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
 * Full license text available in LICENSE.md
 */

#pragma once

using namespace CEG;

// JSON data writer.
class JsonWriter
{
private:

    // Output file stream for writing JSON data to disk.
    std::ofstream m_JsonFileOut;

public:
    
    /**
    * @brief Constructs the class and opens the specified file for writing.
    *
    * @param path The filesystem path where the JSON file will be created/saved.
    * @throws 'std::runtime_error' if the file cannot be opened for writing.
    */
    explicit JsonWriter(
        const fs::path & path
    ) : m_JsonFileOut( path )
    {
        if (!m_JsonFileOut)
            throw std::runtime_error( std::format( "Cannot open '{}' for writing.", path.string() ) );
    }

    ~JsonWriter() = default;
    JsonWriter( const JsonWriter & ) = delete;
    JsonWriter & operator=( const JsonWriter & ) = delete;
    JsonWriter( JsonWriter && ) = default;
    JsonWriter & operator=( JsonWriter && ) = default;
    

    /**
    * @brief Writes all CEG data to the JSON file in a structured format.
    *
    * This method serializes various types of CEG functions:
    * 
    * - CEG protected constant functions.
    * - CEG protected stolen/masked functions.
    * - CEG integrity check functions.
    * - CEG test secret functions.
    * - Crucial CEG information including the version.
    *
     * @throws 'std::runtime_error' if there's an error writing to the file.
     */
    void WriteJSON()
    {
        json j_root;
        json j_array_protected = json::array();
        
        /**
        * @brief Lambda function to add CEG protected functions to the JSON array.
        *
        * @param container The container holding function information.
        * @param type Identifier for the CEG function type (constant and stolen).
        */
        auto add_protected_funcs = [&j_array_protected]( const auto & container, const int type )
        {
            for (const auto& [func, eip_bp] : container)
            {
                // Unpack the tuple of the prologue, EIP and BP.
                auto [prologue, eip, bp] = eip_bp;

                j_array_protected.push_back( {
                    {
                        std::format( "0x{:08x}", func.as<std::uint32_t>() ),
                        {
                            { "Prologue", std::format( "0x{:08x}", prologue.as<std::uint32_t>() ) }, // Function prologue address.
                            { "EIP", std::format( "0x{:08x}", eip.as<std::uint32_t>() ) }, // Current entry point address.
                            { "BP", std::format( "0x{:08x}", bp.as<std::uint32_t>() ) }, // Software breakpoint address.
                            { "Value", "0x00000000" }, // Default CEG value.
                            { "Type", type }, // CEG function type.
                        }
                    }
                    } );
            }
        };
        
        /**
        * @brief Lambda function to add miscellaneous CEG functions to the root JSON.
        *
        * @param container The container holding function addresses.
        * @param name The JSON key name under which to store the function array.
        */
        auto add_funcs = [&j_root]( const auto & container, std::string_view name )
        {
            json j_array = json::array();

            for (const auto & address : container)
                j_array.push_back( std::format( "0x{:08x}", address.as<std::uint32_t>() ) );

            j_root[name] = std::move( j_array );
        };

        add_protected_funcs( Data::CEG_PROTECTED_CONSTANT_FUNCS, 1 ); // CEG protected constant functions.
        add_protected_funcs( Data::CEG_PROTECTED_STOLEN_FUNCS_v1, 2 ); // CEG protected stolen functions (v1).
        add_protected_funcs( Data::CEG_PROTECTED_STOLEN_FUNCS_v2, 3 ); // CEG protected stolen functions (v2).
        add_protected_funcs( Data::CEG_PROTECTED_STOLEN_FUNCS_v3, 4 ); // CEG protected stolen functions (v3).

        // Add core CEG system function addresses.
        j_root["Init"] = std::format( "0x{:08x}", Data::CEG_INIT_LIBRARY_FUNC.as<std::uint32_t>() ); // CEG initialization function.
        j_root["RegisterThread"] = std::format( "0x{:08x}", Data::CEG_REGISTER_THREAD_FUNC.as<std::uint32_t>() ); // CEG thread registration function (main).
        j_root["Terminate"] = std::format( "0x{:08x}", Data::CEG_TERM_LIBRARY_FUNC.as<std::uint32_t>() ); // CEG terminate function.
        j_root["Version"] = Data::CEG_OLD_VERSION ? 1 : 2; // CEG version.

        // Add an array of CEG protected functions (constant and stolen).
        j_root["ConstantOrStolen"] = j_array_protected;

        // Add restart flag (indicates whether the application should be restarted).
        // No restart required by default.
        j_root["ShouldRestart"] = false;

        // Set the breakpoint type used by the handler.
        // '1' is default aka 'Software'.
        j_root["BreakpointType"] = 1;

        add_funcs( Data::CEG_REGISTER_THREAD_FUNC_FUNCS, "RegisterThreads" );  // CEG thread registration functions (all).
        add_funcs( Data::CEG_INTEGRITY_FUNCS, "Integrity" );
        add_funcs( Data::CEG_TESTSECRET_FUNCS, "TestSecret" );

        // Check for the custom module and decide whether it's a dynamic library.
        if ((Data::CEG_IMAGEBASE_RAW >= 0x10000000 && !Data::CEG_MODULENAME.empty()))
            j_root["ModuleName"] = Data::CEG_MODULENAME;

        m_JsonFileOut << j_root.dump( 4 );
        m_JsonFileOut.flush();

        if (m_JsonFileOut.bad())
            throw std::runtime_error( "Error writing to JSON file." );
    }
};