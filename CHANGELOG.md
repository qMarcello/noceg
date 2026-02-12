<a name="1.3.0"></a>
# 1.3.0 (2026-02-12)
- Added support for CEG version `3` with allocated buffers and CPUID checks (`F1 2013™`, `F1 2014™`, `Sid Meier's Civilization®: Beyond Earth™`, `XCOM: Enemy Within`)
- Added additional exports to `steam_api.dll`
- Fixed incorrect address calculations for certain CEG function types
- Fixed detection logic for CEG versions `2` and `3` to correctly distinguish between constant values and relative addresses
- Fixed CEG function scan boundaries (resolves issues with `Total War: SHOGUN 2 Demo`)
<a name="1.2.0"></a>
# 1.2.0 (2026-02-07)
- Added support for `Left 4 Dead 2` and `Portal 2` (older builds)
- Added WinAPI hooks to bypass certain checks in older CEG version (`1`)
- Added additional exports to `steam_api.dll`
<a name="1.1.0"></a>
# 1.1.0 (2025-09-05)
- Enhanced the breakpoint system. You can now select which type to use. Set `"BreakpointType": 2` to enable hardware breakpoints.
- Added support for `Duke Nukem: Forever`.
- Added the new CEG terminate function pattern.
- Added the new "RegisterThreads" patches.
- Removed the ASLR requirement for certain games.
- Updated patches for CEG-protected types `2` and `3`.
- Performed minor code cleanup.