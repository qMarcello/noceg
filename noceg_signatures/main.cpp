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

#include <iostream>

// https://github.com/0x1F9F1/mem
#include <mem/pattern.h>
#include <mem/pattern_cache.h>

// https://github.com/zyantific/zydis
#include <Zydis.h>

// https://github.com/nlohmann/json
#include <json/json.hpp>
using json = nlohmann::json;

// Custom hash specialization for 'mem::pointer' to enable usage in 'std::unordered_set'.
namespace std
{
    template<>
    struct hash<mem::pointer>
    {
        std::size_t operator()( const mem::pointer & p ) const noexcept
        {
            return std::hash<std::uint32_t>{}(p.as<std::uint32_t>());
        }
    };
}

#include <analyzer.h>
#include <writer.h>
#include <patterns.h>

using namespace CEG;

int main( 
    int argc,
    char * argv[] 
)
{
    std::cout << "CEG signatures finder by iArtorias (https://github.com/iArtorias)." << std::endl << std::endl;

    try
    {
        if (argc < 2)
        {
            std::cerr << std::format( "Usage: '{}' <ceg_binary>.", argv[0] ) << std::endl;
            std::cin.get();
            return 1;
        }

        auto read_res = BinaryRead( argv[1] );

        if (!read_res)
        {
            std::cerr << std::format( "[ERROR] '{}'.", ErrorToString( read_res.error() ) ) << std::endl;
            return 1;
        }

        std::string content = read_res.value();

        if (content.empty())
        {
            std::cerr << "[ERROR] Binary content is empty." << std::endl;
            std::cin.get();
            return 1;
        }

        void * address = nullptr;
        std::uint32_t size = 0;
        auto load_res = LoadBinaryImage( content, address, size );

        if (!load_res)
        {
            std::cerr << std::format( "[ERROR] '{}'.", ErrorToString( load_res.error() ) ) << std::endl;
            std::cin.get();
            return 1;
        }

        // Assign the module name.
        Data::CEG_MODULENAME = fs::path( argv[1] ).filename().string();

        // Find out if this is an odler CEG.
        FindFunction( "51 B8 ?? ?? ?? ?? FF D0 59 FF E0", address, 0x20, Data::CEG_OLD_VERSION );

        if (Data::CEG_OLD_VERSION)
            std::cout << "[WARNING] Older CEG version found." << std::endl;

        // Find CEG init function.
        Data::CEG_INIT_LIBRARY_FUNC = FindPatternMatch( CEG_INIT_LIBRARY_FUNC_PATTERNS, address, size );

        if (!Data::CEG_INIT_LIBRARY_FUNC)
        {
            std::cout << "[ERROR] CEG init function not found." << std::endl;
            std::cin.get();
            return 1;
        }

        Data::CEG_INIT_LIBRARY_FUNC = TransformToRealAddress( address, Data::CEG_INIT_LIBRARY_FUNC );
        std::cout << std::format( "[SUCCESS] Found CEG init function: '0x{:08x}'.",
            Data::CEG_INIT_LIBRARY_FUNC.as<std::uint32_t>() ) << std::endl;

        // Find CEG terminate function.
        Data::CEG_TERM_LIBRARY_FUNC = FindPatternMatch( CEG_TERM_LIBRARY_FUNC_PATTERNS, address, size );

        if (!Data::CEG_TERM_LIBRARY_FUNC)
        {
            std::cout << "[ERROR] CEG terminate function not found." << std::endl;
            std::cin.get();
            return 1;
        }

        Data::CEG_TERM_LIBRARY_FUNC = TransformToRealAddress( address, Data::CEG_TERM_LIBRARY_FUNC );
        std::cout << std::format( "[SUCCESS] Found CEG terminate function: '0x{:08x}'.",
            Data::CEG_TERM_LIBRARY_FUNC.as<std::uint32_t>() ) << std::endl;

        // Find CEG register thread functions.
        for (auto & pattern : CEG_REGISTER_THREAD_FUNC_PATTERNS)
            FindFunctions( pattern, address, size, Data::CEG_REGISTER_THREAD_FUNC_FUNCS );

        // Find all CEG protected functions for the further analysis.
        std::vector<mem::pointer> ceg_protect;
        for (auto & pattern : CEG_PROTECT_PATTERNS)
            FindFunctions( pattern, address, size, ceg_protect);

        if (!ceg_protect.empty())
        {
            auto analyzer = std::make_unique<InstructionAnalyzer>();

            auto start = content.substr( Data::CEG_RAW_DATA_POINTER );
            auto data = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(start.data()),
                start.size()
            );

            bool success = analyzer->AnalyzeCEGProtectedFunctions( data, address, ceg_protect );

            if (success)
            {
                // Lambda function to remove duplicate references from CEG protected function maps.
                auto remove_ref = []( const auto & container )
                {
                    for (const auto & [key, _] : container)
                    {
                        auto range = Data::CEG_PROTECTED_STOLEN_FUNCS_v2.equal_range( key );

                        if (range.first != range.second)
                            Data::CEG_PROTECTED_STOLEN_FUNCS_v2.erase( range.first, range.second );
                    }
                };

                // Remove duplicates based on CEG version.
                if(Data::CEG_OLD_VERSION)
                    remove_ref( Data::CEG_PROTECTED_STOLEN_FUNCS_v1 );
                else
                {
                    remove_ref( Data::CEG_PROTECTED_CONSTANT_FUNCS );
                    remove_ref( Data::CEG_PROTECTED_STOLEN_FUNCS_v3 );
                }

                // Print statistics about found CEG protected functions.
                auto print_protected_funcs = []( const auto & map, std::string_view label )
                {
                    if (map.empty())
                        return;

                    auto keys_view = map | std::views::keys;
                    std::set<mem::pointer> unique_keys( keys_view.begin(), keys_view.end() );

                    std::cout << std::format( "[SUCCESS] Found CEG protected {} functions: '{}'.", label, unique_keys.size() ) << std::endl;
                };

                print_protected_funcs( Data::CEG_PROTECTED_STOLEN_FUNCS_v1, "(stolen) (v1)" );
                print_protected_funcs( Data::CEG_PROTECTED_STOLEN_FUNCS_v2, "(stolen) (v2)" );
                print_protected_funcs( Data::CEG_PROTECTED_STOLEN_FUNCS_v3, "(stolen) (v3)" );
                print_protected_funcs( Data::CEG_PROTECTED_CONSTANT_FUNCS, "(constant)" );

                if (!Data::CEG_REGISTER_THREAD_FUNC_FUNCS.empty() && Data::CEG_REGISTER_THREAD_FUNC)
                {
                    Data::CEG_REGISTER_THREAD_FUNC = TransformToRealAddress( address, Data::CEG_REGISTER_THREAD_FUNC );
                    std::cout << std::format( "[SUCCESS] Found CEG register thread function: '0x{:08x}'.",
                        Data::CEG_REGISTER_THREAD_FUNC.as<std::uint32_t>() ) << std::endl;

                    TransformToRealAddress( address, Data::CEG_REGISTER_THREAD_FUNC_FUNCS );
                }
            }
        }

        // Find CEG integrity functions.
        for (auto & pattern : CEG_INTEGRITY_PATTERNS)
            FindFunctions( pattern, address, size, Data::CEG_INTEGRITY_FUNCS );

        if (!Data::CEG_INTEGRITY_FUNCS.empty())
        {
            std::cout << std::format( "[SUCCESS] Found CEG integrity functions: '{}'.", Data::CEG_INTEGRITY_FUNCS.size() ) << std::endl;
            TransformToRealAddress( address, Data::CEG_INTEGRITY_FUNCS );
        }

        // Find CEG test secret functions.
        for (auto & pattern : CEG_TESTSECRET_PATTERNS)
            FindFunctions( pattern, address, size, Data::CEG_TESTSECRET_FUNCS );

        if (!Data::CEG_TESTSECRET_FUNCS.empty())
        {
            std::cout << std::format( "[SUCCESS] Found CEG test secret functions: '{}'.", Data::CEG_TESTSECRET_FUNCS.size() ) << std::endl;
            TransformToRealAddress( address, Data::CEG_TESTSECRET_FUNCS );
        }

        auto writer = std::make_unique<JsonWriter>( fs::path( argv[0] ).parent_path() / "noceg.json" );
        writer->WriteJSON();

        std::cout << std::endl << "Press 'ENTER' key to exit application." << std::endl;
        std::cin.get();
        return 0;
    }
    catch (const std::exception & ex)
    {
        std::cerr << std::format( "[ERROR] '{}'.", ex.what() ) << std::endl;
        std::cin.get();
        return 1;
    }

    return 0;
}