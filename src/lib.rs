//! VMAware – Rust VM Detection Library
//!
//! A faithful port of the VMAware C library.  Provides a simple API for
//! detecting virtual machine environments.
//!
//! # Quick-start
//!
//! ```no_run
//! use vmaware::{detect, brand, percentage};
//!
//! if detect(None) {
//!     println!("Running inside a VM: {}", brand(None).as_str());
//!     println!("Confidence: {}%", percentage(None));
//! }
//! ```

#![allow(clippy::too_many_arguments)]

pub mod core;
pub mod cpu;
pub mod memo;
pub mod techniques;
pub mod types;
pub mod util;

/// Direct syscall (Hell's Gate) module – Windows x86-64 only.
///
/// Provides spoofed NT function wrappers that invoke the `syscall` instruction
/// directly, bypassing ntdll trampolines that AV/EDR software hook.
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod syscall;

pub use types::{Flagset, HyperXState, Technique, VMBrand};

// ── Public API ────────────────────────────────────────────────────────────────

/// Returns `true` when the current environment is detected as a virtual machine.
///
/// Pass `None` to run all applicable techniques, or supply a custom `Flagset`
/// to restrict which techniques are used.
pub fn detect(flags: Option<Flagset>) -> bool {
    let fs = flags.unwrap_or_else(Flagset::all);
    core::detect(fs)
}

/// Returns the most likely VM brand.
pub fn brand(flags: Option<Flagset>) -> VMBrand {
    let fs = flags.unwrap_or_else(Flagset::all);
    core::get_brand(fs)
}

/// Returns the VM confidence as a percentage (0–100).
pub fn percentage(flags: Option<Flagset>) -> u8 {
    let fs = flags.unwrap_or_else(Flagset::all);
    core::get_percentage(fs)
}

/// Returns the number of techniques that returned a positive result.
pub fn detected_count(flags: Option<Flagset>) -> usize {
    let fs = flags.unwrap_or_else(Flagset::all);
    core::detected_technique_count(fs)
}

/// Returns all brands that contributed at least one point.
pub fn multi_brand(flags: Option<Flagset>) -> Vec<VMBrand> {
    let fs = flags.unwrap_or_else(Flagset::all);
    core::get_detected_brands(fs)
}

/// Run a single technique and return whether it fired.
pub fn check(technique: Technique) -> bool {
    let mut fs = Flagset::new();
    fs.set(technique);
    core::run_all(fs, false) > 0
}

/// Hyper-X environment classification.
pub fn hyperx() -> HyperXState {
    util::hyper_x()
}

/// Human-readable conclusion string.
pub fn conclusion(flags: Option<Flagset>) -> String {
    let is_vm = detect(flags);
    let b = brand(flags);
    let pct = percentage(flags);

    if is_vm {
        if b != VMBrand::Invalid {
            format!(
                "This environment is detected as a virtual machine ({}). \
                 VM confidence: {}%.",
                b.as_str(),
                pct
            )
        } else {
            format!(
                "This environment is detected as a virtual machine (unknown brand). \
                 VM confidence: {}%.",
                pct
            )
        }
    } else {
        format!(
            "No virtual machine detected. VM confidence: {}%.",
            pct
        )
    }
}
