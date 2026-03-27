//! Technique modules.

pub mod cross;

#[cfg(windows)]
pub mod win;

#[cfg(target_os = "linux")]
pub mod linux;

// Re-export platform-appropriate Windows stubs for non-Windows so core.rs
// can still compile. The technique table uses #[cfg(windows)] guards, but
// the fn references need to resolve on all platforms during type-checking.
#[cfg(not(windows))]
pub mod win {
    // Empty stub module – Windows techniques are fully guarded by #[cfg(windows)]
    // in core.rs and will never be called/compiled on non-Windows targets.
}

#[cfg(not(target_os = "linux"))]
pub mod linux {
    // Stub for non-Linux platforms.
}
