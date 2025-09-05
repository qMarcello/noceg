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

#include "process.h"

// JSON file reader/writer.
class JsonReader
{
private:

    // The main JSON object.
    json m_JSON;

    // Path to the JSON configuration file.
    fs::path m_JSONPath;

public:
    
    /**
    * @brief Constructs the JSON reader with a specified file path.
    *
    * @param json_file Path to the JSON configuration file.
    */
    explicit JsonReader( 
        const fs::path & json_file
    )
        : m_JSONPath { json_file }
    {}
    
    
    /**
    * @brief Loads JSON data from the specified file.
    *
    * @return 'std::expected<void, Error>' Either success or read/parse failure.
    */
    [[nodiscard]] std::expected<void, Error> LoadJSON() noexcept
    {
        try
        {
            std::ifstream in { m_JSONPath };
            if (!in.is_open())
                return std::unexpected { Error::JsonReadFailed };

            in >> m_JSON;
            return {};
        }
        catch (const std::exception &)
        {
            return std::unexpected { Error::JsonParseFailed };
        }
    }
    
    
    /**
    * @brief Writes the current JSON data to file.
    *
    * @return 'std::expected<void, Error>' Either success or write failure.
    */
    [[nodiscard]] std::expected<void, Error> SaveJSON() const noexcept
    {
        try
        {
            std::ofstream out { m_JSONPath };
            if (!out.is_open())
                return std::unexpected { Error::JsonWriteFailed };

            out << std::setw( 4 ) << m_JSON;
            return {};
        }
        catch (const std::exception &)
        {
            return std::unexpected { Error::JsonWriteFailed };
        }
    }


    /**
    * @brief Provides non-const access to the JSON object.
    *
    * @return Reference to the JSON object.
    */
    [[nodiscard]] json & ReadData() noexcept
    {
        return m_JSON;
    }
    
    
    /**
    * @brief Provides const access to the JSON object.
    *
    * @return Const reference to the JSON object.
    */
    [[nodiscard]] const json & ReadData() const noexcept
    {
        return m_JSON;
    }
    
    /**
    * @brief Updates a specific entry in the 'ConstantOrStolen' array with a new value.
    *
    * Sets the 'Value' field at the specified index using the current EAX register value.
    *
    * @param index Index in the 'ConstantOrStolen' array to update.
    * @param eax The new value to set.
    */
    void UpdateEntry(
        std::size_t index,
        std::uint32_t eax
    )
    {
        auto & entry = m_JSON["ConstantOrStolen"][index];
        auto & data = entry.begin().value();

        data["Value"] = std::format( "0x{:08X}", eax );
    }
};