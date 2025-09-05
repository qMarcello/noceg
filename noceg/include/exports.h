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

// Forwarded SteamAPI exports.
FORWARD_EXPORT_SIMPLE( std::uint32_t, SteamAPI_GetHSteamPipe )
FORWARD_EXPORT_SIMPLE( std::uint32_t, SteamAPI_GetHSteamUser )
FORWARD_EXPORT_SIMPLE( bool, SteamAPI_Init )
FORWARD_EXPORT_SIMPLE( bool, SteamAPI_InitSafe )
FORWARD_EXPORT_SIMPLE( bool, SteamAPI_IsSteamRunning )
FORWARD_EXPORT_VOID_SIMPLE( SteamAPI_Shutdown )
FORWARD_EXPORT_VOID_SIMPLE( SteamAPI_RunCallbacks )
FORWARD_EXPORT( bool, SteamAPI_RestartAppIfNecessary,
(uint32_t unOwnAppID), (unOwnAppID) )
FORWARD_EXPORT_VOID( SteamAPI_SetMiniDumpComment,
    (const char * pchMsg), (pchMsg) )
FORWARD_EXPORT_VOID( SteamAPI_WriteMiniDump,
    (uint32_t uStructuredExceptionCode, void * pvExceptionInfo, uint32_t uBuildID), (uStructuredExceptionCode, pvExceptionInfo, uBuildID) )
FORWARD_EXPORT_VOID( SteamAPI_RegisterCallback,
    (void * pCallback, int iCallback), (pCallback, iCallback) )
FORWARD_EXPORT_VOID( SteamAPI_UnregisterCallback,
    (void * pCallback), (pCallback) )
FORWARD_EXPORT_VOID( SteamAPI_RegisterCallResult,
    (void * pCallback, std::uint64_t hAPICall), (pCallback, hAPICall) )
FORWARD_EXPORT_VOID( SteamAPI_UnregisterCallResult,
    (void * pCallback, std::uint64_t hAPICall), (pCallback, hAPICall) )
FORWARD_EXPORT_SIMPLE( void *, SteamClient )
FORWARD_EXPORT_SIMPLE( void *, SteamUser )
FORWARD_EXPORT_SIMPLE( void *, SteamFriends )
FORWARD_EXPORT_SIMPLE( void *, SteamUtils )
FORWARD_EXPORT_SIMPLE( void *, SteamMasterServerUpdater )
FORWARD_EXPORT_SIMPLE( void *, SteamMatchmaking )
FORWARD_EXPORT_SIMPLE( void *, SteamMatchmakingServers )
FORWARD_EXPORT_SIMPLE( void *, SteamUserStats )
FORWARD_EXPORT_SIMPLE( void *, SteamApps )
FORWARD_EXPORT_SIMPLE( void *, SteamNetworking )
FORWARD_EXPORT_SIMPLE( void *, SteamRemoteStorage )
FORWARD_EXPORT_SIMPLE( void *, SteamScreenshots )
FORWARD_EXPORT_SIMPLE( void *, SteamGameServer )
FORWARD_EXPORT_SIMPLE( void *, SteamGameServerNetworking )
FORWARD_EXPORT_SIMPLE( void *, SteamGameServerUtils )
FORWARD_EXPORT_SIMPLE( bool, SteamGameServer_BSecure )
FORWARD_EXPORT_SIMPLE( std::uint64_t, SteamGameServer_GetSteamID )
FORWARD_EXPORT( bool, SteamGameServer_Init,
    (std::uint32_t unIP, std::uint16_t usSteamPort, std::uint16_t usGamePort, std::uint16_t usQueryPort, int eServerMode,
    const char * pchVersionString), (unIP, usSteamPort, usGamePort, usQueryPort, eServerMode, pchVersionString) )
FORWARD_EXPORT_VOID_SIMPLE( SteamGameServer_Shutdown )
FORWARD_EXPORT_VOID_SIMPLE( SteamGameServer_RunCallbacks )
FORWARD_EXPORT_SIMPLE( void *, SteamGameServerStats )