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

#include <atomic>
#include <chrono>
#include <format>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <ostream>
#include <syncstream>
#include <string>
#include <string_view>

namespace fs = std::filesystem;

namespace Log
{
    // Supported log levels.
    enum class LogLevel : std::uint8_t
    {
        DEBUG = 0, 
        INFO,
        WARNING,
        ERR
    };
    
    /**
    * @brief Converts a 'LogLevel' enum to its corresponding character representation.
    * 
    * @param lvl The log level to convert.
    * @return A character representing the log level.
    */
    constexpr char LogLevelToString( 
        LogLevel lvl
    ) noexcept
    {
        switch (lvl)
        {
            case LogLevel::DEBUG:
                return 'D';
            case LogLevel::INFO:
                return 'I';
            case LogLevel::WARNING:
                return 'W';
            case LogLevel::ERR:
                return 'E';
        }

        return '?';
    }

    // A simple thread safe logger class.
    class Logger
    {
    private:

        // Indicates whether logging is currently enabled.
        inline static std::atomic_bool m_LogEnabled = false;

        // Current minimum log level threshold.
        inline static std::atomic<LogLevel> m_LogLevel = LogLevel::INFO;

        // Mutex to ensure thread safe access to log operations.
        inline static std::mutex m_LogMutex;

        // Output file stream used for writing log messages.
        inline static std::ofstream m_FileStream;

        // Pointer to the active log output stream.
        inline static std::ostream * m_LogStream = nullptr;

    public:
        
        /**
        * @brief Configures the logger for the further usage.
        * 
        * @param path Path to the log file.
        * @param enabled If true, logging is enabled, otherwise disabled.
        * @param append If true, the log is appended to the file, otherwise the file is truncated.
        */
        static void Configure( 
            const fs::path & path,
            bool enabled = false,
            bool append = true ) noexcept
        {
            m_LogEnabled.store( enabled, std::memory_order_relaxed );

            if (!enabled)
                return;

            std::scoped_lock lock { m_LogMutex };

            if (m_FileStream.is_open())
                m_FileStream.close();

            auto mode = std::ios::out | (append ? std::ios::app : std::ios::trunc);

            m_FileStream.open( path, mode );

            m_LogStream = static_cast<std::ostream *>(&m_FileStream);
        }
        
        
        /**
        * @brief Sets the minimum log level for messages to be emitted.
        * 
        * @param lvl The minimum log level.
        */
        static void SetLevel( 
            LogLevel lvl
        ) noexcept
        {
            m_LogLevel.store( lvl, std::memory_order_relaxed );
        }
        
        
        /**
        * @brief Logs a formatted message if logging is enabled and the log level is sufficient.
        * 
        * @tparam Args Argument types for formatting.
        * @param lvl The level of the message.
        * @param fmt The format string.
        * @param args The arguments to format.
        */
        template<typename... Args>
        static void Log(
            LogLevel lvl,
            std::string_view fmt,
            Args&&... args
        )
        {
            if (!m_LogEnabled.load( std::memory_order_relaxed ) ||
                lvl < m_LogLevel.load( std::memory_order_relaxed ))
                return;

            // Get the current timestamp.
            auto now = std::chrono::system_clock::now();
            auto ts = std::format( "{:%Y-%m-%d %H:%M:%S}", now );

            // Format the message string.
            auto msg = std::vformat( fmt, std::make_format_args( args... ) );

            std::scoped_lock lock { m_LogMutex };
            std::osyncstream oss { *m_LogStream };
            oss << ts
                << " [" << LogLevelToString( lvl ) << "] "
                << msg << '\n';
            oss.flush();
        }
    };


    // Easy to access macros.
    #define LOG_DEBUG(...) Log::Logger::Log(Log::LogLevel::DEBUG, __VA_ARGS__)
    #define LOG_INFO(...) Log::Logger::Log(Log::LogLevel::INFO, __VA_ARGS__)
    #define LOG_WARNING(...) Log::Logger::Log(Log::LogLevel::WARNING, __VA_ARGS__)
    #define LOG_ERROR(...) Log::Logger::Log(Log::LogLevel::ERR, __VA_ARGS__)
}
