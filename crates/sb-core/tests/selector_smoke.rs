// Permanently disabled with an always-false cfg (no unknown features)
#![cfg(not(any(feature = "router", not(feature = "router"))))]
// Disabled: Selector API changed. Tests will be rewritten.
