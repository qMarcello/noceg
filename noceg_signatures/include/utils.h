/*
 * This software is licensed under the NoCEG Non-Commercial Copyleft License.
 *
 * Copyright (C) 2025-2026 iArtorias <iartorias.re@gmail.com>
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

#include <Windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_set>
#include <filesystem>
#include <fstream>
#include <format>
#include <expected>

namespace fs = std::filesystem;

namespace CEG
{
    // Enumeration representing possible error states in the application.
    enum class Error
    {
        FileNotFound,
        FileReadError,
        InvalidPattern,
        DecoderInitFailed,
        InvalidAddress,
        EmptyContent,
        NullBaseAddress,
        InvalidDOSHeader,
        InvalidPEHeader,
        NullImageBase,
        EmptyNtHeader,
        NullRawPointer,
        NullVirtualSize,
        FileWriteError,
        OutputFileCreateError
    };


    /**
    * @brief Converts an 'Error' enum value to a human readable string description.
    *
    * @param error The 'Error' enum value to convert.
    * @return A string containing the error description.
    */
    std::string ErrorToString(
        Error error
    )
    {
        switch (error)
        {
            case Error::FileNotFound:
                return "File not found.";

            case Error::FileReadError:
                return "File read error.";

            case Error::InvalidPattern:
                return "Invalid pattern.";

            case Error::DecoderInitFailed:
                return "Decoder initialization failed.";

            case Error::InvalidAddress:
                return "Invalid address.";

            case Error::EmptyContent:
                return "Binary content is empty.";

            case Error::NullBaseAddress:
                return "The base address is null.";

            case Error::InvalidDOSHeader:
                return "Invalid DOS signature.";

            case Error::InvalidPEHeader:
                return "Invalid PE signature.";

            case Error::NullImageBase:
                return "ImageBase is null.";

            case Error::EmptyNtHeader:
                return "NT header structure is empty.";

            case Error::NullRawPointer:
                return "Raw pointer address is null.";

            case Error::NullVirtualSize:
                return "Section virtual size is null.";

            case Error::FileWriteError:
                return "An error has occured while writing to the file.";

            case Error::OutputFileCreateError:
                return "An error has occured while trying to open the output file.";
        }

        return {};
    }

    namespace Data
    {
        // Maximum number of bytes to scan when searching for CEG patterns.
        inline constexpr std::uint32_t CEG_SCAN_SIZE = 300;

        // Base address of the code section.
        inline std::uint32_t CEG_CODE_BASE = 0;

        // Raw 'ImageBase' value from the PE header.
        inline std::uint32_t CEG_IMAGEBASE_RAW = 0;

        // Memory address where the binary content is loaded.
        inline std::uint32_t CEG_IMAGEBASE_MEMORY = 0;

        // Virtual address of the first section.
        inline std::uint32_t CEG_VIRTUAL_ADDRESS = 0;

        // File offset to the raw data of the first section.
        inline std::uint32_t CEG_RAW_DATA_POINTER = 0;

        // Name of the CEG module.
        inline std::string CEG_MODULENAME {};

        // A map of CEG protected stolen/masked functions.
        inline std::multimap<mem::pointer, std::tuple<mem::pointer, mem::pointer, mem::pointer>> CEG_PROTECTED_STOLEN_FUNCS_v1 {}; // v1
        inline std::multimap<mem::pointer, std::tuple<mem::pointer, mem::pointer, mem::pointer>> CEG_PROTECTED_STOLEN_FUNCS_v2 {}; // v2
        inline std::multimap<mem::pointer, std::tuple<mem::pointer, mem::pointer, mem::pointer>> CEG_PROTECTED_STOLEN_FUNCS_v3 {}; // v3

        // A map of CEG protected constant functions.
        inline std::multimap<mem::pointer, std::tuple<mem::pointer, mem::pointer, mem::pointer>> CEG_PROTECTED_CONSTANT_FUNCS {};

        // Set of CEG protected constant functions that have an associated value.
        // Only used by the newest CEG version.
        inline std::set<mem::pointer> CEG_PROTECTED_CONSTANT_FUNCS_VALUES {};

        // Functions related to CEG thread registration.
        inline std::unordered_set<mem::pointer> CEG_REGISTER_THREAD_FUNC_FUNCS {};

        // Vector of CEG integrity functions.
        inline std::vector<mem::pointer> CEG_INTEGRITY_FUNCS {};

        // Vector of CEG test secret functions.
        inline std::vector<mem::pointer> CEG_TESTSECRET_FUNCS {};

        // Address of the CEG library initialization function.
        inline mem::pointer CEG_INIT_LIBRARY_FUNC = nullptr;

        // Address of the CEG terminate function.
        inline mem::pointer CEG_TERM_LIBRARY_FUNC = nullptr;

        // Address of the CEG register thread function.
        inline mem::pointer CEG_REGISTER_THREAD_FUNC = nullptr;

        // Pointer indicating if this is an older version of CEG.
        inline mem::pointer CEG_OLD_VERSION = nullptr;

        // Indicates if this is the newest version of CEG.
        inline mem::pointer CEG_NEW_VERSION = nullptr;

        // Breakpoint address for the newest CEG.
        // 
        // mov eax,dword ptr ds : [ecx]
        // not eax
        // mov dword ptr ds : [ecx], eax <-- 
        // ret
        inline mem::pointer CEG_NEW_BREAKPOINT = nullptr;
    }

    template<typename T>
    using Result = std::expected<T, Error>;

    /**
    * @brief Reads the entire binary file into a string.
    *
    * @param binary The path to the binary file to read.
    * @return 'Result<std::string>' containing the file content or an error.
    * @retval 'std::string' The complete file content if successful.
    * @retval 'FileNotFound' if the file cannot be opened.
    * @retval 'FileReadError' if reading fails.
    */
    [[nodiscard]] Result<std::string> BinaryRead(
        const fs::path & binary
    )  noexcept
    {
        std::ifstream file( binary, std::ios::binary | std::ios::ate );

        if (!file)
            return std::unexpected( Error::FileNotFound );

        const auto size = static_cast<std::uint32_t>(file.tellg());
        file.seekg( 0, std::ios::beg );

        std::string data( size, '\0' );
        if (!file.read( data.data(), size ))
            return std::unexpected( Error::FileReadError );

        return data;
    }


    /**
    * @brief Loads and analyzes a PE binary image, extracting the required addresses.
    *
    * @param content The binary file content.
    * @param address [out] Reference to pointer that will receive the code section address.
    * @param size [out] The code section size.
    * @return 'std::expected<void, Error>' Either success or specific error.
    */
    [[nodiscard]] std::expected<void, Error> LoadBinaryImage(
        std::string_view content,
        void *& address,
        std::uint32_t & size
    ) noexcept
    {
        if (content.empty())
            return std::unexpected( Error::EmptyContent );

        Data::CEG_IMAGEBASE_MEMORY = reinterpret_cast<std::uint32_t>(content.data());
        if (Data::CEG_IMAGEBASE_MEMORY == 0)
            return std::unexpected( Error::NullBaseAddress );

        const auto * dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(Data::CEG_IMAGEBASE_MEMORY);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            return std::unexpected( Error::InvalidDOSHeader );

        auto * nt_headers = reinterpret_cast<IMAGE_NT_HEADERS *>(
            reinterpret_cast<std::uint8_t *>(Data::CEG_IMAGEBASE_MEMORY) + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
            return std::unexpected( Error::InvalidPEHeader );

        if (nt_headers->OptionalHeader.ImageBase == 0)
            return std::unexpected( Error::NullImageBase );

        Data::CEG_IMAGEBASE_RAW = nt_headers->OptionalHeader.ImageBase;

        const auto * section_header = IMAGE_FIRST_SECTION( nt_headers );
        if (!section_header)
            return std::unexpected( Error::EmptyNtHeader );

        if (section_header->PointerToRawData == 0)
            return std::unexpected( Error::NullRawPointer );

        Data::CEG_RAW_DATA_POINTER = section_header->PointerToRawData;

        address = reinterpret_cast<void *>(
            Data::CEG_IMAGEBASE_MEMORY + Data::CEG_RAW_DATA_POINTER);

        size = static_cast<std::uint32_t>(section_header->Misc.VirtualSize);
        if (size == 0)
            return std::unexpected( Error::NullVirtualSize );

        Data::CEG_VIRTUAL_ADDRESS = section_header->VirtualAddress;
        Data::CEG_CODE_BASE = Data::CEG_IMAGEBASE_RAW + Data::CEG_VIRTUAL_ADDRESS;

        return {};
    }


    // Valid address types.
    template<typename T>
    concept AddressType = std::is_pointer_v<T> || std::is_integral_v<T>;

    /**
    * @brief Searches for a single occurrence of a byte pattern within a memory region.
    *
    * @tparam The address type.
    * @param pattern The byte pattern to search for.
    * @param address Starting address of the memory region to search.
    * @param size Size in bytes of the memory region to search.
    * @return 'mem::pointer' pointing to the match, or nullptr if not found.
    */
    template<AddressType T>
    [[nodiscard]] mem::pointer FindFunction(
        std::string_view pattern,
        T address,
        const std::uint32_t size
    ) noexcept
    {
        try
        {
            mem::pattern needle( pattern.data() );
            mem::default_scanner scanner( needle );

            mem::region region( address, size );

            return scanner.scan( region );
        }
        catch (...)
        {
            return mem::pointer { nullptr };
        }
    }


    /**
    * @brief Searches for a single occurrence of a byte pattern within a memory region.
    *
    * @tparam The address type.
    * @param pattern The byte pattern to search for.
    * @param address Starting address of the memory region to search.
    * @param size Size in bytes of the memory region to search.
    * @param res [out] Reference to 'mem::pointer' that will receive the search result.
    */
    template<AddressType T>
    [[nodiscard]] void FindFunction(
        std::string_view pattern,
        T address,
        const std::uint32_t size,
        mem::pointer & res
    )
    {
        try
        {
            mem::pattern needle( pattern.data() );
            mem::default_scanner scanner( needle );

            mem::region region( address, size );
            res = scanner.scan( region );
        }
        catch (...)
        {
            res = mem::pointer { nullptr };
        }
    }


    /**
    * @brief Searches for all occurrences of a byte pattern and appends results to a vector.
    *
    * @tparam The address type.
    * @param pattern The byte pattern to search for.
    * @param address Starting address of the memory region to search.
    * @param size Size in bytes of the memory region to search.
    * @param res [out] Reference to vector that will receive all found addresses.
    */
    template<AddressType T>
    [[nodiscard]] void FindFunctions(
        std::string_view pattern,
        T address,
        const std::uint32_t size,
        std::vector<mem::pointer> & res
    )
    {
        try
        {
            mem::pattern needle( pattern.data() );
            mem::default_scanner scanner( needle );

            mem::region region( address, size );

            auto found = scanner.scan_all( region );
            res.insert( res.end(), found.begin(), found.end() );
        }
        catch (...)
        {}
    }


    /**
    * @brief Searches for all occurrences of a byte pattern and appends results to a vector.
    *
    * @tparam The address type.
    * @param pattern The byte pattern to search for.
    * @param address Starting address of the memory region to search.
    * @param size Size in bytes of the memory region to search.
    * @param res [out] Reference to unordered set that will receive all found addresses.
    */
    template<AddressType T>
    [[nodiscard]] void FindFunctions(
        std::string_view pattern,
        T address,
        const std::uint32_t size,
        std::unordered_set<mem::pointer> & res
    )
    {
        try
        {
            mem::pattern needle( pattern.data() );
            mem::default_scanner scanner( needle );

            mem::region region( address, size );

            auto found = scanner.scan_all( region );
            res.insert( found.begin(), found.end() );
        }
        catch (...)
        {}
    }


    /**
    * @brief Attempts to find a match using multiple patterns, returning the first successful match.
    *
    * @param patterns Container of pattern strings to search for.
    * @param address Starting address of the memory region to search.
    * @param size Size in bytes of the memory region to search.
    * @return 'mem::pointer' to the first matching pattern, or nullptr if no patterns match.
    */
    [[nodiscard]] mem::pointer FindPatternMatch(
        const auto & patterns,
        void* address,
        DWORD size
    ) noexcept
    {
        for (const auto & pattern : patterns)
        {
            if (auto result = FindFunction( pattern, address, size ))
                return result;
        }

        return nullptr;
    }


    /**
    * @brief Calculates the real virtual address for the target binary.
    *
    * @param address_start Pointer to the beginning of the memory region.
    * @param address_current The current address in memory.
    * @return 'mem::pointer' containing the calculated real virtual address.
    */
    [[nodiscard]] constexpr mem::pointer CalculateRealAddress(
        const void * address_start,
        const std::uint32_t address_current
    ) noexcept
    {
        return Data::CEG_CODE_BASE + (address_current - reinterpret_cast<std::uint32_t>(address_start));
    }


    /**
    * @brief Transforms a range of memory addresses to their corresponding real addresses.
    *
    * @param start Pointer to the beginning of the original memory region.
    * @param addresses Range of addresses to transform.
    */
    void TransformToRealAddress(
        const void * start,
        std::ranges::range auto & addresses
    ) noexcept
    {
        std::transform( addresses.begin(), addresses.end(), addresses.begin(),
            [start]( mem::pointer addr )
        {
            return CalculateRealAddress( start, addr.as<std::uint32_t>() );
        } );
    }


    /**
    * @brief Transforms a set of memory addresses to their corresponding real addresses.
    *
    * @param start Pointer to the beginning of the original memory region.
    * @param addresses A set of addresses to transform.
    */
    void TransformToRealAddress(
        const void * start,
        std::unordered_set<mem::pointer> & addresses
    ) noexcept
    {
        std::unordered_set<mem::pointer> transformed;

        std::transform( addresses.begin(), addresses.end(),
            std::inserter( transformed, transformed.begin() ),
            [start]( mem::pointer addr )
        {
            return CalculateRealAddress( start, addr.as<std::uint32_t>() );
        } );

        addresses = std::move( transformed );
    }


    /**
    * @brief Transforms a single memory address to its corresponding real address.
    *
    * @param start Pointer to the beginning of the original memory region.
    * @param address Reference to the address to transform.
    * @return 'mem::pointer' containing the transformed real address.
    */
    mem::pointer TransformToRealAddress(
        const void * start,
        mem::pointer & address
    ) noexcept
    {
        return CalculateRealAddress( start, address.as<std::uint32_t>() );
    }


    /**
    * @brief Converts a virtual address to its corresponding file offset.
    *
    * @param va Virtual address to convert.
    * @return The calculated file offset.
    */
    [[nodiscard]] constexpr std::uint32_t VaToOffset(
        std::uint32_t va
    ) noexcept
    {
        std::uint32_t rva = va - Data::CEG_IMAGEBASE_RAW;

        rva -= Data::CEG_VIRTUAL_ADDRESS;
        rva += Data::CEG_RAW_DATA_POINTER;

        return Data::CEG_IMAGEBASE_MEMORY + rva;
    }


    /**
    * @brief Calculates the relative virtual address between two virtual addresses.
    *
    * @param va Base virtual address.
    * @param va_cmp Target virtual address to compare against.
    * @return The required RVA address.
    */
    [[nodiscard]] constexpr std::uint32_t VaToRva(
        std::uint32_t va,
        std::uint32_t va_cmp
    ) noexcept
    {
        return va_cmp - va;
    }
}