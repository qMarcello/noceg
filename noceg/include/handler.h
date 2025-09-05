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

// Automatically restarts the current application if the restart flag is set.
static void RestartApp()
{
    auto * state = ApplicationManager::GetInstance();
    if (state->GetShouldRestart())
    {
        // Attempt to restart the application.
        if (auto res = ProcessManager::SelfRestart(); !res)
            LOG_ERROR( "Error restarting app '0x{:08X}'", static_cast<int>(res.error()) );
    }
}


// A custom exception handler.
LONG CALLBACK CEGExceptionHandler(
    PEXCEPTION_POINTERS ei
) noexcept
{
    auto * state = ApplicationManager::GetInstance();
    if (!state)
        return EXCEPTION_CONTINUE_SEARCH;

    auto * ctx = ei->ContextRecord;
    const auto code = ei->ExceptionRecord->ExceptionCode;

    // Update the current CEG entry.
    auto update_ceg_entry = [&state, &ctx]()
    {
        LOG_INFO( "Breakpoint just being hit, EAX value is '0x{:08X}'.", ctx->Eax );

        auto & config = state->GetJSON();
        const auto & json = config.ReadData();
        const auto index = state->GetCurrentIndex();

        if (index < json["ConstantOrStolen"].size())
        {
            // Update the JSON entry with the result value from EAX.
            config.UpdateEntry( index, ctx->Eax );

            if (auto res = config.SaveJSON(); !res)
                LOG_WARNING( "Failed to update an entry inside 'noceg.json'." );
            else
            {
                if (json.value( "ShouldRestart", false ))
                {
                    LOG_INFO( "Setting the restart flag." );
                    state->SetShouldRestart();

                    // Change EIP to point to the restart function.
                    ctx->Eip = reinterpret_cast<DWORD>(RestartApp);
                }
                else
                {
                    // Restore the previously saved context.
                    ctx = state->GetContext();
                    state->SetCurrentIndex( index + 1 );

                    // Continue to next entry.
                    state->GetEntryProcessorManager().ProcessEntry();
                }
            }
        }
    };

    switch (code)
    {
        // Custom software exception thrown by the tool.
        case 0xCEADDEAD:
        {
            LOG_INFO( "Custom exception reached '0xCEADDEAD'." );

            // Save the current CPU context for future use.
            state->SetContext( ctx );
            ctx->Eip = static_cast<DWORD>(state->GetEipAddress());

            LOG_INFO( "Changing EIP to '0x{:08X}'.", ctx->Eip );

            // Set trap flag to trigger a single-step exception after the next instruction.
            ctx->EFlags |= 0x100;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        case EXCEPTION_SINGLE_STEP:
        {
            if (ctx->Eip == state->GetTargetAddress())
            {
                LOG_INFO( "Target CEG function reached '0x{:08X}'.", ctx->Eip );

                // Clear trap flag.
                ctx->EFlags &= ~0x100;
            }

            auto & bp = state->GetBreakpointManager();
            if (bp.GetBreakpointType() == BreakpointType::Hardware)
            {
                if (ctx->Eip == bp.GetAddress())
                {
                    if (bp.IsSet())
                    {
                        LOG_INFO( "Removing the hardware breakpoint at '0x{:08X}'.", ctx->Eip );
                        bp.RemoveBreakpoint();
                    }

                    update_ceg_entry();
                }
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        case EXCEPTION_BREAKPOINT:
        {
            auto & bp = state->GetBreakpointManager();
            if (bp.GetBreakpointType() == BreakpointType::Software)
            {
                if (ctx->Eip == bp.GetAddress())
                {
                    if (bp.IsSet())
                    {
                        LOG_INFO( "Removing the software breakpoint at '0x{:08X}'.", ctx->Eip );
                        bp.RemoveBreakpoint();
                    }

                    update_ceg_entry();

                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            break;
        }

        // Cover this specific case.
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        {
            auto * state = ApplicationManager::GetInstance();
            if (state->GetShouldRestart())
            {
                LOG_WARNING( "Caught some illegal instruction, forcing exit." );
                std::exit( 1 );
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}