# vmaware

A **VM / hypervisor / sandbox detection library** for Rust – a faithful port of
the [VMAware C library](https://github.com/kernelwernel/VMAware) with additional
Windows-focused hardening.

[![Crates.io](https://img.shields.io/crates/v/novmforbroadcom.svg)](https://crates.io/crates/novmforbroadcom)
[![Docs.rs](https://docs.rs/novmforbroadcom/badge.svg)](https://docs.rs/novmforbroadcom)
[![GitHub](https://img.shields.io/badge/GitHub-TomGousseau%2FVmawareRust-blue?logo=github)](https://github.com/TomGousseau/VmawareRust)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **GitHub**: https://github.com/TomGousseau/VmawareRust  
> **Crates.io**: https://crates.io/crates/novmforbroadcom

---

## Features

| Feature | Description |
|---------|-------------|
| 86 detection techniques | CPUID tricks, registry keys, driver lists, BIOS strings, firmware, kernel objects, and more |
| **Hell's Gate + Halo's Gate** | On Windows x86-64, all `NtQuerySystemInformation` / `NtOpenDirectoryObject` calls are issued via **direct `syscall`** instructions, completely bypassing the ntdll trampolines that Windows Defender ATP and other EDR products hook |
| Cross-platform | Compiles on Windows, Linux, and macOS; platform-appropriate techniques are selected automatically |
| `no_std`-friendly API surface | The public API (`detect`, `brand`, `percentage`, `check`) is simple and allocation-light |
| Single-header usable as a library | Add it to `Cargo.toml` and call `vmaware::detect(None)` |

---

## Quick start

```toml
# Cargo.toml
[dependencies]
vmaware = "0.2"
```

```rust
use vmaware::{detect, brand, percentage, VMBrand};

fn main() {
    if detect(None) {
        println!("Virtual machine detected!");
        println!("Brand:      {}", brand(None).as_str());
        println!("Confidence: {}%", percentage(None));
    } else {
        println!("No VM detected (confidence: {}%)", percentage(None));
    }
}
```

---

## API

```rust
/// Returns true when a virtual machine is detected.
/// Pass `None` to run all applicable techniques.
pub fn detect(flags: Option<Flagset>) -> bool;

/// Returns the most likely VM brand.
pub fn brand(flags: Option<Flagset>) -> VMBrand;

/// VM confidence as a percentage (0–100).
pub fn percentage(flags: Option<Flagset>) -> u8;

/// Number of techniques that fired.
pub fn detected_count(flags: Option<Flagset>) -> usize;

/// All brands that contributed evidence.
pub fn multi_brand(flags: Option<Flagset>) -> Vec<VMBrand>;

/// Run a single technique by ID.
pub fn check(technique: Technique) -> bool;

/// Hyper-X environment classification (RealVM / ArtifactVM / Enlightenment).
pub fn hyperx() -> HyperXState;

/// Human-readable conclusion string.
pub fn conclusion(flags: Option<Flagset>) -> String;
```

---

## Selective technique execution

Use a `Flagset` to run only the techniques you care about:

```rust
use vmaware::{check, Technique, Flagset};

// Run a single named technique
let found = check(Technique::VmwareBackdoor);

// Run a custom subset
let mut fs = Flagset::new();
fs.set(Technique::HypervisorBit);
fs.set(Technique::Vmid);
fs.set(Technique::CpuBrand);

if vmaware::detect(Some(fs)) {
    println!("Hypervisor detected via CPUID probes");
}
```

---

## Syscall spoofing (Windows x86-64)

EDR products such as Windows Defender ATP install **userland hooks** by
overwriting the first few bytes of sensitive ntdll stubs with a `jmp` to their
monitoring code.  When `NtQuerySystemInformation` is called to enumerate loaded
drivers or query hypervisor information, the EDR intercepts the call and can
flag or block it.

VMAware avoids this by implementing **Hell's Gate**:

1. The PEB (`gs:[0x60]`) is walked directly to find ntdll's in-memory base  
   address — no `GetModuleHandle` call.
2. ntdll's PE export table is parsed in-place to locate each NT stub's VA.
3. The syscall number is read from the clean stub bytes  
   (`4C 8B D1 B8 XX XX XX XX` = `mov r10,rcx ; mov eax,<nr>`).
4. If a stub is hooked (starts with `E9`/jmp), **Halo's Gate** recovers the  
   correct number by scanning ±32 neighbouring stubs whose numbers are  
   sequential.
5. The `syscall` instruction is executed directly from our own code page,  
   never passing through any hooked ntdll trampoline.

The public `vmaware::syscall` module exposes the resolver if you want to use
it in your own code:

```rust
#[cfg(all(windows, target_arch = "x86_64"))]
fn example() {
    // Resolve the syscall number for any NT function.
    if let Some(nr) = vmaware::syscall::resolve("NtQuerySystemInformation") {
        println!("NtQuerySystemInformation syscall nr = {:#x}", nr);
    }
}
```

---

## Supported VM brands (70+)

VMware, VirtualBox, QEMU/KVM, Hyper-V, Xen, Parallels, Docker, WSL, Bochs,
DBVM, VPC, Sandboxie, Cuckoo, Wine, BlueStacks, Azure Hyper-V, AWS Nitro,
GCE, OpenStack, AMD SEV/SEV-ES/SEV-SNP, and many more.

---

## Platform support

| Platform     | Supported | Notes |
|--------------|-----------|-------|
| Windows x86-64 | ✅ Full | Hell's Gate syscall spoofing active |
| Windows ARM64 | ✅ Partial | Syscall spoofing falls back to GetProcAddress |
| Linux x86-64 | ✅ Full | 31 Linux-specific techniques |
| macOS x86-64 / arm64 | ⚠️ Partial | 6 macOS techniques (stubs for rest) |

---

## Detection threshold

A VM is declared when the accumulated technique score reaches **150 points**  
out of a maximum of **300 points** (`HIGH_THRESHOLD_SCORE`).  Individual  
technique scores range from 10 (low confidence, e.g. BootLogo) to 100  
(definitive, e.g. VMware backdoor port, VmID CPUID response).

---

## License

MIT – see [LICENSE](../LICENSE).  
Original C/C++ library by [kernelwernel](https://github.com/kernelwernel/VMAware).
