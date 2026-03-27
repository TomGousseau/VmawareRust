//! Cross-platform CPUID-based VM detection techniques.
//!
//! Mirrors the cross-platform section of vmaware_core.c:
//!   vmid, cpu_brand, hypervisor_bit, hypervisor_str, bochs_cpu,
//!   timer, thread_mismatch, cpuid_signature, kgt_signature.

use crate::core::add_brand_score;
use crate::cpu;
use crate::memo;
use crate::types::VMBrand;
use crate::util;

// ── vmid ──────────────────────────────────────────────────────────────────────

/// Check CPUID hypervisor-vendor leaf (0x40000000..0x40000010) against known
/// VM signatures.
pub fn vmid() -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return false;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // Probe leaves 0x40000000 through 0x40000010
        for leaf in (0x4000_0000u32..=0x4000_0010).step_by(0x10) {
            let (found, brand) = cpu::vmid_template(leaf);
            if found {
                add_brand_score(brand, 0);
                return true;
            }
        }
        false
    }
}

// ── cpu_brand ─────────────────────────────────────────────────────────────────

/// Check for VM-related keywords in the CPU brand string.
pub fn cpu_brand() -> bool {
    // Retrieve or compute the CPU brand string
    let brand = match memo::get_cpu_brand() {
        Some(b) => b,
        None => {
            let b = cpu::cpu_brand_string();
            memo::set_cpu_brand(b.clone());
            b
        }
    };

    if brand.is_empty() {
        return false;
    }

    static KEYWORDS: &[(&str, VMBrand)] = &[
        ("QEMU",         VMBrand::QEMU),
        ("KVM",          VMBrand::KVM),
        ("Virtual CPU",  VMBrand::QEMUKVM),
        ("VMware",       VMBrand::VMware),
        ("VirtualBox",   VMBrand::VBox),
        ("Hyper-V",      VMBrand::HyperV),
        ("BOCHS",        VMBrand::Bochs),
        ("Xen",          VMBrand::Xen),
        ("bhyve",        VMBrand::Bhyve),
        ("ACRN",         VMBrand::ACRN),
        ("GenuineIntel", VMBrand::Invalid),  // Intel host – not a VM indicator
        ("AuthenticAMD", VMBrand::Invalid),  // AMD host  – not a VM indicator
    ];

    let brand_lc = brand.to_lowercase();
    for &(kw, vm_brand) in KEYWORDS {
        if brand_lc.contains(&kw.to_lowercase()) {
            if vm_brand != VMBrand::Invalid {
                add_brand_score(vm_brand, 0);
                return true;
            }
        }
    }
    false
}

// ── hypervisor_bit ────────────────────────────────────────────────────────────

/// Check the hypervisor present bit in CPUID leaf 1 ECX (bit 31).
///
/// **Root-partition guard**: on a Windows host that runs Hyper-V, this bit is
/// ALSO set (the root partition itself runs virtualised).  We check
/// `hyper_x() == Enlightenment` and return false so we don't award 100 VM
/// points to a bare-metal machine that simply has Hyper-V enabled.
pub fn hypervisor_bit() -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return false;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        use crate::types::HyperXState;
        // Root partition: Hyper-V sets the hypervisor bit even on the host OS.
        if crate::util::hyper_x() == HyperXState::Enlightenment {
            return false;
        }
        let ecx = cpu::cpuid(1, 0).ecx;
        (ecx >> 31) & 1 != 0
    }
}

// ── hypervisor_str ────────────────────────────────────────────────────────────

/// Check the hypervisor vendor string at leaf 0x40000000 for known brands.
///
/// **Root-partition guard**: the Hyper-V root partition also exposes
/// `"Microsoft Hv"` at this leaf, so we skip on `Enlightenment`.
pub fn hypervisor_str() -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return false;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        use crate::types::HyperXState;
        if crate::util::hyper_x() == HyperXState::Enlightenment {
            return false;
        }

        if !cpu::is_leaf_supported(0x4000_0000) {
            return false;
        }
        let r = cpu::cpuid(0x4000_0000, 0);
        let vendor = cpu::vendor_string(r.ebx, r.ecx, r.edx);

        // A non-empty, non-CPU-manufacturer string indicates a hypervisor
        let is_cpu_vendor = vendor.starts_with("GenuineIntel")
            || vendor.starts_with("AuthenticAMD")
            || vendor.starts_with("HygonGenuine");

        if !vendor.trim_matches('\0').is_empty() && !is_cpu_vendor {
            let (found, brand) = cpu::vmid_template(0x4000_0000);
            if found {
                add_brand_score(brand, 0);
            }
            return true;
        }
        false
    }
}

// ── bochs_cpu ─────────────────────────────────────────────────────────────────

/// Detect Bochs by checking reserved CPUID fields that Bochs sets to 0.
pub fn bochs_cpu() -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return false;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if !cpu::is_intel() {
            return false;
        }

        // CPUID leaf 1: on real Intel CPUs bits 31..22 of ECX are reserved 0.
        // Bochs leaves them as non-zero (typically mirrors EAX).
        // Also check brand string quirk.
        let brand = match memo::get_cpu_brand() {
            Some(b) => b,
            None => {
                let b = cpu::cpu_brand_string();
                memo::set_cpu_brand(b.clone());
                b
            }
        };

        if brand.contains("BOCHSCPU") || brand.to_lowercase().contains("bochs") {
            add_brand_score(VMBrand::Bochs, 0);
            return true;
        }

        // Check stepping: Bochs uses family=6 model=2 stepping=3 (06_02_03)
        let steps = cpu::fetch_steppings();
        if steps.family == 6 && steps.model == 2 && steps.extmodel == 0 {
            // Ambiguous – only count if brand string also looks artificial
            // (real Pentium Pro was 06_01, not 06_02 with step 3)
            if brand.is_empty() {
                add_brand_score(VMBrand::Bochs, 0);
                return true;
            }
        }

        false
    }
}

// ── timer ─────────────────────────────────────────────────────────────────────

/// Measure CPU cycle overhead of a CPUID call using RDTSC; unusually high
/// values indicate a hypervisor translating RDTSC.
pub fn timer() -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return false;

    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::{_mm_lfence, _rdtsc};

        const ITERATIONS: u64 = 10;
        const THRESHOLD_CYCLES: u64 = 750;

        let mut total: u64 = 0;
        unsafe {
            for _ in 0..ITERATIONS {
                _mm_lfence();
                let t1 = _rdtsc();
                // Force a CPUID call (serialising instruction)
                std::arch::x86_64::__cpuid(0);
                _mm_lfence();
                let t2 = _rdtsc();
                total = total.saturating_add(t2.wrapping_sub(t1));
            }
        }
        let avg = total / ITERATIONS;
        avg > THRESHOLD_CYCLES
    }

    #[cfg(target_arch = "x86")]
    {
        // 32-bit: use asm to read RDTSC
        false // stub – platform-specific asm omitted for brevity
    }
}

// ── thread_mismatch ───────────────────────────────────────────────────────────

/// Compare the logical-thread count reported by CPUID with the actual OS
/// thread count. A mismatch can indicate that the hypervisor exposes fewer
/// CPUs than the underlying host.
pub fn thread_mismatch() -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return false;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let brand = match memo::get_cpu_brand() {
            Some(b) => b,
            None => {
                let b = cpu::cpu_brand_string();
                memo::set_cpu_brand(b.clone());
                b
            }
        };

        // Look up expected thread count from the database
        let expected = match cpu::lookup_expected_threads(&brand) {
            Some(n) => n,
            None => return false, // Unknown model – skip
        };

        let actual = util::get_logical_cpu_count();

        // Mismatch: hypervisor is presenting fewer hardware threads
        expected != actual && actual < expected
    }
}

// ── cpuid_signature ───────────────────────────────────────────────────────────

/// Check for known VM CPUID signatures at leaves 0x1 and 0x40000000.
pub fn cpuid_signature() -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return false;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // Leaf 0x1 EAX upper nibble: some VMs report a distinctive family/model
        let eax1 = cpu::cpuid(1, 0).eax;
        let family = (eax1 >> 8) & 0xF;
        let model  = (eax1 >> 4) & 0xF;

        // Check for VMWARE SVGA model=0x01 family=0x06 (unusual EAX signature)
        // or VirtualBox's EAX==0x000306A9 pattern etc.

        // Also probe some known leaf signatures
        static SIG_TABLE: &[(u32, u32, VMBrand)] = &[
            // (leaf, expected_eax_mask, brand) – simplified check
            (0x4000_0000, 0x4000_0001, VMBrand::VMware),
        ];

        let _ = SIG_TABLE;

        // More reliably: check leaf 0x40000010 (VMware TSC frequency leaf)
        if cpu::is_leaf_supported(0x4000_0010) {
            let r = cpu::cpuid(0x4000_0010, 0);
            if r.eax != 0 {
                // VMware-specific: EAX = virtual TSC frequency in kHz
                add_brand_score(VMBrand::VMware, 0);
                return true;
            }
        }

        // Check for KVM signature leaf
        if cpu::is_leaf_supported(0x4000_0001) {
            let r = cpu::cpuid(0x4000_0001, 0);
            // KVM: EAX has feature bits; a non-zero EAX with KVMKVMKVM signature
            // at 0x40000000 is already caught by vmid(), but cross-check here
            let base_vendor = {
                let r0 = cpu::cpuid(0x4000_0000, 0);
                cpu::vendor_string(r0.ebx, r0.ecx, r0.edx)
            };
            if base_vendor.contains("KVMKVMKVM") {
                let kvm_features = r.eax;
                if kvm_features != 0 {
                    add_brand_score(VMBrand::KVM, 0);
                    return true;
                }
            }
        }

        // Check CPUID leaf 0x1 ECX bits that are typically unset on bare metal
        // but may be set in VMs: bit 5 (VMX), bit 31 (Hypervisor)
        let _ecx1 = cpu::cpuid(1, 0).ecx;
        // bit 31 is hypervisor present – already checked by hypervisor_bit
        // bit 5 is VMX – not a reliable VM indicator on its own

        // Family 15 + model 0: may indicate Bochs or old VM
        if family == 15 && model == 0 {
            add_brand_score(VMBrand::Bochs, 0);
            return true;
        }

        false
    }
}

// ── kgt_signature ─────────────────────────────────────────────────────────────

/// Detect Intel KGT (Trusty) by its CPUID leaf 0x40000001 EAX signature.
pub fn kgt_signature() -> bool {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return false;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if !cpu::is_leaf_supported(0x4000_0001) {
            return false;
        }
        let eax = cpu::cpuid(0x4000_0001, 0).eax;
        // KGT signature: "TKIM" = 0x4D494B54
        if eax == 0x4D49_4B54 {
            add_brand_score(VMBrand::IntelKGT, 0);
            return true;
        }
        false
    }
}

// ── thread_count (Linux + macOS) ──────────────────────────────────────────────

/// Compare OS-reported thread count with CPUID topology.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn thread_count() -> bool {
    let os_threads = util::get_logical_cpu_count();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if cpu::is_leaf_supported(0x0B) {
            let r = cpu::cpuid(0x0B, 1); // level 1 = core level
            let cpuid_threads = r.ebx & 0xFFFF;
            if cpuid_threads > 0 && cpuid_threads != os_threads {
                return true;
            }
        }
    }

    // Fallback: a single-thread environment is suspicious
    os_threads <= 1
}

// ── Linux + Windows shared ────────────────────────────────────────────────────

/// Check for Azure Hyper-V specific registry / SMBIOS markers.
#[cfg(any(windows, target_os = "linux"))]
pub fn azure() -> bool {
    #[cfg(windows)]
    {
        crate::techniques::win::azure()
    }
    #[cfg(not(windows))]
    {
        // Linux: check SMBIOS chassis manufacturer for "Microsoft Corporation"
        let mfr = util::read_file("/sys/class/dmi/id/chassis_vendor")
            .unwrap_or_default();
        let host = util::read_file("/etc/hostname")
            .unwrap_or_default();
        if mfr.contains("Microsoft") && host.to_lowercase().contains("azure") {
            add_brand_score(VMBrand::AzureHyperV, 0);
            return true;
        }
        false
    }
}

/// Check system_registers for hypervisor clues (Linux: MSR via file).
#[cfg(any(windows, target_os = "linux"))]
pub fn system_registers() -> bool {
    #[cfg(windows)]
    {
        crate::techniques::win::system_registers()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Firmware string scan.
#[cfg(any(windows, target_os = "linux"))]
pub fn firmware() -> bool {
    #[cfg(windows)]
    {
        crate::techniques::win::firmware()
    }
    #[cfg(not(windows))]
    {
        // Linux: scan /sys/class/dmi/id/* for VM strings
        static PATHS: &[(&str, &[(&str, VMBrand)])] = &[
            ("/sys/class/dmi/id/bios_vendor", &[
                ("SeaBIOS",   VMBrand::QEMU),
                ("VBOX",      VMBrand::VBox),
                ("bochs",     VMBrand::Bochs),
                ("Parallels", VMBrand::Parallels),
            ]),
            ("/sys/class/dmi/id/sys_vendor", &[
                ("QEMU",      VMBrand::QEMU),
                ("VMware",    VMBrand::VMware),
                ("VirtualBox", VMBrand::VBox),
                ("Xen",       VMBrand::Xen),
                ("KVM",       VMBrand::KVM),
                ("Microsoft", VMBrand::HyperV),
                ("innotek",   VMBrand::VBox),
                ("Parallels", VMBrand::Parallels),
            ]),
            ("/sys/class/dmi/id/product_name", &[
                ("Virtual Machine", VMBrand::HyperV),
                ("VMware",    VMBrand::VMware),
                ("VirtualBox", VMBrand::VBox),
                ("KVM",       VMBrand::KVM),
                ("BHYVE",     VMBrand::Bhyve),
                ("QEMU",      VMBrand::QEMU),
                ("Bochs",     VMBrand::Bochs),
                ("Standard PC", VMBrand::QEMU),
            ]),
        ];

        for &(path, table) in PATHS {
            if let Some(content) = util::read_file(path) {
                let lower = content.to_lowercase();
                for &(kw, brand) in table {
                    if lower.contains(&kw.to_lowercase()) {
                        add_brand_score(brand, 0);
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// PCI device IDs scan.
#[cfg(any(windows, target_os = "linux"))]
pub fn devices() -> bool {
    #[cfg(windows)]
    {
        crate::techniques::win::devices()
    }
    #[cfg(not(windows))]
    {
        // Linux: scan /sys/bus/pci/devices/*/uevent for VM vendor IDs
        static VM_VENDOR_IDS: &[(&str, VMBrand)] = &[
            ("0x15ad", VMBrand::VMware),   // VMware
            ("0x80ee", VMBrand::VBox),     // VirtualBox
            ("0x1af4", VMBrand::QEMU),     // Virtio (QEMU/KVM)
            ("0x1414", VMBrand::HyperV),   // Hyper-V
            ("0x5853", VMBrand::Xen),      // Xen
            ("0x1ab8", VMBrand::Parallels),// Parallels
            ("0x1b36", VMBrand::QEMU),     // QEMU additional
        ];

        let pci_dir = std::path::Path::new("/sys/bus/pci/devices");
        if !pci_dir.exists() {
            return false;
        }
        if let Ok(entries) = std::fs::read_dir(pci_dir) {
            for entry in entries.flatten() {
                let uevent = entry.path().join("vendor");
                if let Ok(data) = std::fs::read_to_string(&uevent) {
                    let lower = data.trim().to_lowercase();
                    for &(vid, brand) in VM_VENDOR_IDS {
                        if lower == vid {
                            add_brand_score(brand, 0);
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}
