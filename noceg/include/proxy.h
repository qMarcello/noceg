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

// The dynamic library wrapper utility.
class DllWrapper
{
private:

    // Handle to the original dynamic library.
    HMODULE m_OriginalDll;

    // Cache of exported function names and their resolved addresses.
    std::unordered_map<std::string, FARPROC> m_ExportCache;

    // Path to the original dynamic library on disk.
    std::string m_OriginalDllPath;

    // Name of the wrapper dynamic library.
    std::string m_WrapperDllName;

    // Loads the original dynamic library.
    void LoadOriginalDll()
    {
        m_OriginalDll = LoadLibraryA( m_OriginalDllPath.c_str() );

        if (!m_OriginalDll)
        {
            const DWORD error = GetLastError();
            LOG_ERROR( "Failed to load original library ('{}'). Last error is '{}'.", m_OriginalDllPath, error );
            return;
        }
    }

public:
    
    /**
    * @brief Constructs a new instance and loads the original dynamic library.
    * 
    * @param original_dll Full path to the original dynamic library.
    * @param dll Name of the wrapper dynamic library.
    */
    explicit DllWrapper(
        const std::string & original_dll,
        const std::string & dll )
        : m_OriginalDll( nullptr ),
        m_OriginalDllPath( original_dll ),
        m_WrapperDllName( dll )
    {
        LoadOriginalDll();
    }

    ~DllWrapper()
    {
        if (m_OriginalDll)
            FreeLibrary( m_OriginalDll );
    }

    DllWrapper( const DllWrapper & ) = delete;
    DllWrapper & operator=( const DllWrapper & ) = delete;
    

    /**
    * @brief Retrieves a function pointer from the original dynamic library by name.
    * 
    * @tparam FuncType The expected function type.
    * @param name The name of the exported function.
    * @return A function pointer of the requested type, or nullptr if not found.
    */
    template<typename FuncType>
    FuncType GetFunction( 
        const std::string & name
    )
    {
        if (!m_OriginalDll)
        {
            LOG_ERROR( "Original library ('{}') is not loaded.", m_OriginalDllPath );
            return nullptr;
        }

        // Check the export cache first.
        auto it = m_ExportCache.find( name );
        if (it != m_ExportCache.end())
            return reinterpret_cast<FuncType>(it->second);

        // Resolve the function from the dynamic library.
        const FARPROC proc = GetProcAddress( m_OriginalDll, name.c_str() );

        if (!proc)
            LOG_WARNING( "Function '{}' not found in '{}'.", name, m_OriginalDllPath );

        // Cache the result for future lookups.
        m_ExportCache[name] = proc;
        return reinterpret_cast<FuncType>(proc);
    }
};


// A wrapper to manage a global instance for exclusive Steam API dynamic library usage.
class SteamAPIWrapper
{
private:

    static inline std::unique_ptr<DllWrapper> m_DllWrapper = nullptr;

public:
    
    /**
    * @brief Constructs the wrapper with the given paths.
    * 
    * @param original_dll Path to the original Steam API dynamic library.
    * @param dll Name of the wrapper dynamic library.
    */
    explicit SteamAPIWrapper(
        const std::string & original_dll,
        const std::string & dll )
    {
        if (!m_DllWrapper)
            m_DllWrapper = std::make_unique<DllWrapper>( original_dll, dll );
    }


    // Initializes the global wrapper instance with default dynamic library paths.
    static void Initialize()
    {
        if (!m_DllWrapper)
            m_DllWrapper = std::make_unique<DllWrapper>( "steam_api_org.dll", "steam_api.dll" );
    }


    // Shuts down the global wrapper instance and unloads the dynamic library.
    static void Shutdown()
    {
        m_DllWrapper.reset();
    }
    
    
    /**
    * @brief Retrieves a reference to the global wrapper instance.
    * 
    * Initializes the instance with default paths if not already initialized.
    * @return Reference to the 'DllWrapper' instance.
    */
    static DllWrapper & GetInstance()
    {
        if (!m_DllWrapper)
            Initialize();

        return *m_DllWrapper;
    }
};


// Easy to access macros.
#define FORWARD_EXPORT(ret, name, params, args) \
    extern "C" __declspec(dllexport) ret name params { \
        using func_t = ret(*) params; \
        static func_t func = SteamAPIWrapper::GetInstance().GetFunction<func_t>(#name); \
        return func args; \
    }

#define FORWARD_EXPORT_VOID(name, params, args) \
    extern "C" __declspec(dllexport) void name params { \
        using func_t = void(*) params; \
        static func_t func = SteamAPIWrapper::GetInstance().GetFunction<func_t>(#name); \
        func args; \
    }

#define FORWARD_EXPORT_SIMPLE(ret, name) \
    extern "C" __declspec(dllexport) ret name() { \
        using func_t = ret(*)(); \
        static func_t func = SteamAPIWrapper::GetInstance().GetFunction<func_t>(#name); \
        return func(); \
    }

#define FORWARD_EXPORT_VOID_SIMPLE(name) \
    extern "C" __declspec(dllexport) void name() { \
        using func_t = void(*)(); \
        static func_t func = SteamAPIWrapper::GetInstance().GetFunction<func_t>(#name); \
        func(); \
    }