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
 * Full license text available in LICENSE
 */

#pragma once

// Forward declaration of the custom exception handler.
LONG CALLBACK CEGExceptionHandler(
    PEXCEPTION_POINTERS ei
) noexcept;

class EntryProcessorManager;

// The global application state manager.
class ApplicationManager
{
private:

    // Manages the lifecycle of the vectored exception handler.
    std::unique_ptr<void, decltype(&RemoveVectoredExceptionHandler)> m_ExceptionHandler;

    // Default image base address used as the reference point.
    std::uintptr_t m_DefaultImageBase { 0x00400000 };

    // Target image base address of the loaded module.
    std::uintptr_t m_TargetImageBase { 0x00400000 };

    // The current module image size.
    std::uintptr_t m_ImageSize { 0 };

    // Memory address of the targeted CEG protected function.
    std::atomic<std::uintptr_t> m_TargetAddress { 0 };

    // Manages software breakpoints.
    std::unique_ptr<BreakpointManager> m_BreakpointManager;

    // Entry point to which execution will be redirected.
    std::uintptr_t m_EipAddress { 0 };

    // Current index inside the JSON configuration array.
    std::size_t m_CurrentIndex { 0 };

    // Address of the CEG register thread function.
    std::uintptr_t m_RegisterThreadAddress { 0 };

    // JSON configuration reader/writer.
    std::unique_ptr<JsonReader> m_JsonReader;

    // CEG function entry processor.
    std::unique_ptr<EntryProcessorManager> m_EntryProcessorManager;

    // Restart application flag.
    std::atomic_bool m_ShouldRestart { false };

    // Optional saved CPU context from the custom exception handler.
    std::optional<CONTEXT *> m_Context {};

    static inline ApplicationManager * m_Instance { nullptr };

public:

    /**
    * @brief Constructor initializes all managers and sets up singleton instance.
    *
    * Initializes the exception handler, creates the breakpoint manager,
    * loads JSON configuration and registers this instance as the singleton.
    * 
    * @param json_file A full path to 'noceg.json'.
    */
    explicit ApplicationManager( 
        const fs::path & json_file 
    )
        : m_ExceptionHandler { nullptr, &RemoveVectoredExceptionHandler }
        , m_BreakpointManager { std::make_unique<BreakpointManager>() }
        , m_JsonReader { std::make_unique<JsonReader>( json_file ) }
        , m_EntryProcessorManager { std::make_unique<EntryProcessorManager>( this ) }
    {
        m_Instance = this;
    }

    ~ApplicationManager() noexcept
    {
        m_Instance = nullptr;
    }


    /**
     * @brief Gets the singleton instance.
     *
     * @return Pointer to the singleton instance.
     */
    static ApplicationManager * GetInstance() noexcept
    {
        return m_Instance;
    }
    
    
    /**
    * @brief Sets the default image base value to be used as the reference point.
    *
    * @param base The base address to set as the default image base.
    */
    void SetDefaultImageBase(
        const std::uintptr_t base 
    ) noexcept
    {
        m_DefaultImageBase = base;
    }


    /**
    * @brief Sets the target image base address for a specific module.
    *
    *
    * @param module_name The name of the module.
    * If empty, the current executable's base address is used.
    */
    void SetTargetImageBase(
        const std::string & module_name
    ) noexcept
    {
        auto set_image_size = [this]( const HMODULE & mod )
        {
            // Read image size from PE header.
            if (const auto image_size = GetModuleImageSize( mod ))
                m_ImageSize = image_size;
        };

        if (module_name.empty())
        {
            const HMODULE module = GetModuleHandleA( nullptr );
            m_TargetImageBase = reinterpret_cast<std::uintptr_t>(module);

            set_image_size( module );
            return;
        }

        // Validates that a module exports the 'CreateInterface' function.
        constexpr auto is_source_engine_dll = []( HMODULE module ) noexcept -> bool
        {
            return module != nullptr && GetProcAddress( module, "CreateInterface" ) != nullptr;
        };

        // Try to get already loaded module.
        if (HMODULE module = GetModuleHandleA( module_name.c_str() ))
        {
            m_TargetImageBase = reinterpret_cast<std::uintptr_t>(module);

            set_image_size( module );
            return;
        }

        // Module not loaded, try game-specific paths.
        auto lower_name = module_name | std::views::transform( []( std::uint8_t c )
        {
            return std::tolower( c );
        } ) | std::ranges::to<std::string>();

        if (lower_name == "client.dll" || lower_name == "server.dll")
        {
            constexpr std::array games = { "left4dead2", "portal2" };

            for (const auto & game : games)
            {
                const auto path = std::format( "..\\{}\\bin\\{}", game, lower_name );

                if (HMODULE module = LoadLibraryA( path.c_str() );
                    is_source_engine_dll( module ))
                {
                    m_TargetImageBase = reinterpret_cast<std::uintptr_t>(module);

                    set_image_size( module );
                    return;
                }
            }
        }
    }


    /**
     * @brief Registers a vectored exception handler for breakpoint processing.
     *
     * @param handler Function pointer to the exception handler callback.
     */
    void SetExceptionHandler(
        PVECTORED_EXCEPTION_HANDLER handler
    ) noexcept
    {
        if (auto * eh = AddVectoredExceptionHandler( 1, handler ))
            m_ExceptionHandler.reset( eh );
    }


    /**
     * @brief Get for the target CEG function address.
     *
     * @return Target CEG function address.
     */
    [[nodiscard]] std::uintptr_t GetTargetAddress() const noexcept
    {
        return m_TargetAddress.load();
    }
    

    /**
     * @brief Setter for the target CEG function address.
     *
     * @param address Memory address of the target CEG function.
     */
    void SetTargetAddress(
        std::uintptr_t address
    ) noexcept
    {
        m_TargetAddress.store( address );
    }


    /**
     * @brief Gets reference to the breakpoint manager.
     *
     * @return Reference to the 'BreakpointManager' instance.
     */
    [[nodiscard]] BreakpointManager & GetBreakpointManager() noexcept
    {
        return *m_BreakpointManager;
    }


    /**
     * @brief Gets reference to the JSON configuration reader.
     *
     * @return Reference to the 'JsonReader' instance.
     */
    [[nodiscard]] JsonReader & GetJSON() noexcept
    {
        return *m_JsonReader;
    }
    
    
    /**
    * @brief Gets reference to the entries processor.
    *
    * @return Reference to the 'EntryProcessorManager' instance.
    */
    [[nodiscard]] EntryProcessorManager & GetEntryProcessorManager() noexcept
    {
        return *m_EntryProcessorManager;
    }


    /**
     * @brief Gets the entry point address.
     *
     * @return The current entry point address.
     */
    [[nodiscard]] std::uintptr_t GetEipAddress() const noexcept
    {
        return m_EipAddress;
    }


    /**
     * @brief Sets the new entry point.
     *
     * @param address The new entry point address.
     */
    void SetEipAddress(
        std::uintptr_t address
    ) noexcept
    {
        m_EipAddress = address;
    }


    /**
     * @brief Gets the current processing index in the JSON configuration array.
     *
     * @return Current index being processed in the "ConstantOrStolen" array.
     */
    [[nodiscard]] std::size_t GetCurrentIndex() const noexcept
    {
        return m_CurrentIndex;
    }


    /**
     * @brief Sets the current processing index.
     *
     * @param index Index to resume processing from in the JSON array.
     */
    void SetCurrentIndex(
        std::size_t index
    ) noexcept
    {
        m_CurrentIndex = index;
    }


    /**
     * @brief Gets the CEG register thread function address.
     *
     * @return Memory address of the CEG register thread function.
     */
    [[nodiscard]] std::uintptr_t GetRegisterThreadAddress() const noexcept
    {
        return m_RegisterThreadAddress;
    }


    /**
     * @brief Sets the CEG register thread function address.
     *
     * @param address Memory address of the CEG register thread function.
     */
    void SetRegisterThreadAddress(
        std::uintptr_t address
    ) noexcept
    {
        m_RegisterThreadAddress = address;
    }
    
    
    /**
    * @brief Sets the restart flag, indicating the application should restart.
    */
    void SetShouldRestart() noexcept
    {
        m_ShouldRestart.store( true );
    }


    /**
     * @brief Gets the restart application flag state.
     */
    bool GetShouldRestart() noexcept
    {
        return m_ShouldRestart.load();
    }
    
    
    /**
    * @brief Saves the current context.
    *
    * @param ctx Pointer to 'CONTEXT' structure to store.
    */
    void SetContext(
        CONTEXT * ctx
    ) noexcept
    {
        m_Context = std::make_optional( ctx );
    }
    
    
    /**
    * @brief Retrieves the previously saved context.
    *
    * @return Pointer to 'CONTEXT' structure.
    */
    CONTEXT * GetContext() const noexcept
    {
        return m_Context.value();
    }
    
    
    /**
    * @brief Gets the default image base address.
    *
    * @return The base address of the module.
    */
    std::uintptr_t GetDefaultImageBase() const noexcept
    {
        return m_DefaultImageBase;
    }
    
    
    /**
    * @brief Gets the currently stored target image base address.
    *
    * @return The runtime base address of the target module.
    */
    std::uintptr_t GetTargetImageBase() const noexcept
    {
        return m_TargetImageBase;
    }


    /**
    * @brief Translates an address from the default image base
    * to the target image base.
    *
    * @param address The address relative to the default image base.
    * @return The relocated address relative to the target image base.
    */
    std::uintptr_t CalculateRealAddress( 
        const std::uintptr_t address
    ) const noexcept
    {
        if (!address)
            return 0;

        return (address - m_DefaultImageBase) + m_TargetImageBase;
    }
    
    
    /**
    * @brief Gets the size of image from a module's PE header.
    */
    [[nodiscard]] std::uintptr_t GetModuleImageSize(
        HMODULE module
    ) noexcept
    {
        if (!module)
            return 0;

        const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;

        const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<std::uintptr_t>(module) + dos_header->e_lfanew);

        if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
            return 0;

        return static_cast<std::uintptr_t>(
            nt_headers->OptionalHeader.SizeOfImage);
    }
    
    
    /**
    * @brief Gets the size of image from a module's PE header.
    */
    [[nodiscard]] std::uintptr_t GetImageSize()
    {
        return m_ImageSize;
    }
    
    
    /**
    * @brief Translates an address from the target image base
    * back to the default image base.
    *
    * @param address The address relative to the target image base.
    * @return The relocated address relative to the default image base.
    */
    std::uintptr_t CalculateDefaultAddress(
        const std::uintptr_t address
    ) const noexcept
    {
        if (!address)
            return 0;

        const auto size = m_ImageSize > 0 ? m_ImageSize : 0x02000000;

        const bool is_in_target_range =
            (address >= m_TargetImageBase) &&
            (address < m_TargetImageBase + size);

        if (is_in_target_range)
            return (address - m_TargetImageBase) + m_DefaultImageBase;

        return address;
    }
};