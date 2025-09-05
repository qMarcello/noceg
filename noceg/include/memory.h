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

enum class BreakpointType : std::uint8_t
{
    Software = 1,
    Hardware = 2
};

enum class HardwareBreakCondition : DWORD
{
    Execute = 0, // Break on instruction execution.
    Write = 1, // Break on data write.
    Access = 3  // Break on read/write access.
};

enum class HardwareBreakSize : DWORD
{
    One = 0, // 1 byte.
    Two = 1, // 2 bytes.
    Four = 3 // 4 bytes.
};

// Memory protection manager.
class MemoryManager
{
private:

    // Pointer to the memory region being managed.
    void * m_Address { nullptr };

    // Size of the memory region in bytes.
    std::size_t m_Size { 0 };

    // Original protection flags to restore later.
    DWORD m_OldProtection { 0 };

public:

    /**
     * @brief Constructor that changes memory protection for a given region.
     *
     * @param address Pointer to the start of the memory region to protect.
     * @param size Size of the memory region in bytes.
     * @param new_protection New protection flags.
     */
    MemoryManager( void * address, std::size_t size, DWORD new_protection ) noexcept
        : m_Address { address }, m_Size { size }
    {
        if (!VirtualProtect( address, size, new_protection, &m_OldProtection ))
            m_Address = nullptr;
    }

    /**
     * @brief Destructor that restores original memory protection.
     */
    ~MemoryManager() noexcept
    {
        if (m_Address)
            VirtualProtect( m_Address, m_Size, m_OldProtection, &m_OldProtection );
    }

    MemoryManager( const MemoryManager & ) = delete;
    MemoryManager & operator=( const MemoryManager & ) = delete;


    /**
     * @brief Check if the memory manager is in a valid state.
     *
     * @return true if the memory protection change was successful, false otherwise.
     */
    [[nodiscard]] bool IsValid() const noexcept
    {
        return m_Address != nullptr;
    }
};


// Software breakpoint manager.
class BreakpointManager
{
private:

    // Memory address where the breakpoint is set.
    std::uintptr_t m_Address { 0 };

    // Original byte value at the breakpoint address.
    std::uint8_t m_BackupByte { 0 };

    // Flag indicating if a breakpoint is currently active.
    bool m_IsSet { false };

    // Which debug register slot is used (0–3).
    int m_Slot { -1 };

    // The thread handle where the breakpoint is applied.
    HANDLE m_Thread { nullptr };
    
    // Breakpoint type to be used.
    // 'Software' is default.
    BreakpointType m_BreakpointType { BreakpointType::Software };

public:


    /**
     * @brief Sets a software breakpoint at the specified memory address.
     *
     * @param address The memory address where to place the breakpoint.
     */
    [[nodiscard]] void SetSoftwareBreakpoint(
        std::uintptr_t address
    ) noexcept
    {
        if (m_IsSet)
            return;

        auto memory = MemoryManager { reinterpret_cast<void *>(address), 1, PAGE_EXECUTE_READWRITE };
        if (!memory.IsValid())
            return;

        m_Address = address;
        m_BackupByte = *reinterpret_cast<std::uint8_t *>(address);
        *reinterpret_cast<std::uint8_t *>(address) = 0xCC;

        FlushInstructionCache( GetCurrentProcess(), reinterpret_cast<void *>(address), 1 );

        m_IsSet = true;
    }


    /**
     * @brief Sets a hardware breakpoint on the current thread.
     *
     * @param address Address to monitor.
     * @param slot Debug register slot (0–3).
     * @param type Break condition (execute, write, access).
     * @param size Size of watched memory (1, 2, 4 bytes).
     */
    [[nodiscard]] void SetHardwareBreakpoint(
        std::uintptr_t address,
        std::int32_t slot = 0,
        HardwareBreakCondition type = HardwareBreakCondition::Execute,
        HardwareBreakSize size = HardwareBreakSize::One
    ) noexcept
    {
        if (m_IsSet || slot < 0 || slot > 3)
            return;

        CONTEXT ctx {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        m_Thread = GetCurrentThread();
        if (!GetThreadContext( m_Thread, &ctx ))
            return;

        // Assign address to DRx register
        switch (slot)
        {
            case 0: 
                ctx.Dr0 = address;
                break;

            case 1:
                ctx.Dr1 = address; 
                break;

            case 2: 
                ctx.Dr2 = address; 
                break;

            case 3:
                ctx.Dr3 = address;
                break;
        }

        // Clear bits for this slot
        ctx.Dr7 &= ~(0xF << (slot * 4));

        // Local enable for this slot
        ctx.Dr7 |= (1 << (slot * 2));

        // Set type & size in DR7
        ctx.Dr7 |= ((static_cast<DWORD>(type) & 0x3) << (16 + slot * 4));
        ctx.Dr7 |= ((static_cast<DWORD>(size) & 0x3) << (18 + slot * 4));

        if (!SetThreadContext( m_Thread, &ctx ))
            return;

        m_Address = address;
        m_Slot = slot;
        m_IsSet = true;
    }
    
    
    /**
    * @brief Sets either software or hardware breakpoint at the specified memory address.
    *
    * @param address The memory address where to place the breakpoint.
    */
    [[nodiscard]] void SetBreakpoint( 
        std::uintptr_t address
    ) noexcept
    {
        switch (m_BreakpointType)
        {
            case BreakpointType::Software:
            {
                SetSoftwareBreakpoint( address );
                break;
            }

            case BreakpointType::Hardware:
            {
                SetHardwareBreakpoint( address );
                break;
            }
        }
    }


    // Removes the currently set breakpoint and restores original code.
    [[nodiscard]] void RemoveSoftwareBreakpoint() noexcept
    {
        if (!m_IsSet)
            return;

        auto memory = MemoryManager { reinterpret_cast<void *>(m_Address), 1, PAGE_EXECUTE_READWRITE };
        if (!memory.IsValid())
            return;

        *reinterpret_cast<std::uint8_t *>(m_Address) = m_BackupByte;
        FlushInstructionCache( GetCurrentProcess(), reinterpret_cast<void *>(m_Address), 1 );

        m_IsSet = false;
    }


    // Removes the currently set hardware breakpoint.
    [[nodiscard]] void RemoveHardwareBreakpoint() noexcept
    {
        if (!m_IsSet || !m_Thread)
            return;

        CONTEXT ctx {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext( m_Thread, &ctx ))
            return;

        // Disable this slot.
        ctx.Dr7 &= ~(0xF << (m_Slot * 4));

        // Clear DRx register.
        switch (m_Slot)
        {
            case 0:
                ctx.Dr0 = 0;
                break;

            case 1:
                ctx.Dr1 = 0;
                break;

            case 2:
                ctx.Dr2 = 0;
                break;

            case 3:
                ctx.Dr3 = 0;
                break;
        }

        SetThreadContext( m_Thread, &ctx );

        m_Address = 0;
        m_Slot = -1;
        m_IsSet = false;
    }


    // Removes either software of hardware breakpoint.
    [[nodiscard]] void RemoveBreakpoint() noexcept
    {
        switch (m_BreakpointType)
        {
            case BreakpointType::Software:
            {
                RemoveSoftwareBreakpoint();
                break;
            }

            case BreakpointType::Hardware:
            {
                RemoveHardwareBreakpoint();
                break;
            }
        }
    }

    /**
     * @brief Gets the memory address where the breakpoint is set.
     *
     * @return The memory address of the breakpoint, or '0' if no breakpoint is set.
     */
    [[nodiscard]] std::uintptr_t GetAddress() const noexcept
    {
        return m_Address;
    }


    /**
    * @brief Checks if a breakpoint is currently active.
    *
    * @return true if a breakpoint is set, false otherwise.
    */
    [[nodiscard]] bool IsSet() const noexcept
    {
        return m_IsSet;
    }


    // Sets the breakpoint type.
    void SetBreakpointType( 
        const std::int32_t type
    ) noexcept
    {
        switch (type)
        {
            case 1:
            {
                m_BreakpointType = BreakpointType::Software;
                break;
            }

            case 2:
            {
                m_BreakpointType = BreakpointType::Hardware;
                break;
            }
        }
    }


    /**
    * @brief Gets the current breakpoint type.
    *
    * @return either 'Software' or 'Hardware'.
    */
    [[nodiscard]] BreakpointType GetBreakpointType() const noexcept
    {
        return m_BreakpointType;
    }


    /**
     * @brief Destructor that automatically removes any active breakpoint.
     */
    ~BreakpointManager() noexcept
    {
        if (m_IsSet)
        {
            switch (m_BreakpointType)
            {
                case BreakpointType::Software:
                {
                    RemoveSoftwareBreakpoint();
                    break;
                }

                case BreakpointType::Hardware:
                {
                    RemoveHardwareBreakpoint();
                    break;
                }
            }
        }
    }
};