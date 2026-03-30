//! Linux-specific VM detection techniques.

#![cfg(target_os = "linux")]

use crate::core::add_brand_score;
use crate::types::VMBrand;
use crate::util;

// ── smbios_vm_bit ─────────────────────────────────────────────────────────────

/// Check the SMBIOS Chassis Type for values that are exclusively used by VMs.
///
/// Only chassis types that are **never** assigned to real physical hardware are
/// checked to avoid false positives.  In practice the SMBIOS spec assigns:
///   0x00 = Undefined/Unknown (not produced by real OEMs)
///   0x01 = Other (used by QEMU/VirtualBox but also some real embedded boards)
///   0x0D = All-in-One … real OEM types
///
/// VMs that set chassis type to the explicitly "Other" (1) or "Unknown" (2)
/// value while simultaneously setting the vendor to an empty/generic string
/// are a reliable indicator.  We tighten the check: require that the vendor
/// field is also absent or generic.
pub fn smbios_vm_bit() -> bool {
    let chassis = util::read_file("/sys/class/dmi/id/chassis_type")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);

    // Only values that real OEM machines never use:
    //   0 = undefined, 14 = Sub Notebook, 34-35 = tablet form factors
    // 1 and 2 are excluded here alone (too common on real hardware) but
    // combined with a missing/empty vendor they're a valid indicator.
    let vendor = util::read_file("/sys/class/dmi/id/sys_vendor")
        .unwrap_or_default();
    let vendor = vendor.trim().to_lowercase();

    // Chassis types that only appear inside VMs:
    //   1 ("Other") + no real vendor  →  QEMU/VirtualBox without DMI data
    //   2 ("Unknown") + no real vendor → Same
    let vm_only_chassis = chassis == 1 || chassis == 2;
    let no_real_vendor = vendor.is_empty()
        || vendor == "none"
        || vendor == "to be filled by o.e.m."
        || vendor == "default string";

    if vm_only_chassis && no_real_vendor {
        return true;
    }

    false
}

// ── kmsg ─────────────────────────────────────────────────────────────────────

/// Scan /dev/kmsg or /var/log/kern.log for VM-related kernel messages.
pub fn kmsg() -> bool {
    static VM_STRINGS: &[(&str, VMBrand)] = &[
        ("VMware VMCI",      VMBrand::VMware),
        ("VirtualBox",       VMBrand::VBox),
        ("QEMU",             VMBrand::QEMU),
        ("Booting paravirtualized kernel", VMBrand::KVM),
        ("Hypervisor detected", VMBrand::Invalid),
        ("kvm-clock",        VMBrand::KVM),
        ("hv_vmbus",         VMBrand::HyperV),
    ];

    let paths = ["/proc/kmsg", "/var/log/kern.log", "/var/log/syslog"];
    for path in &paths {
        if let Some(content) = util::read_file(path) {
            for &(kw, brand) in VM_STRINGS {
                if content.contains(kw) {
                    if brand != VMBrand::Invalid {
                        add_brand_score(brand, 0);
                    }
                    return true;
                }
            }
        }
    }
    false
}

// ── cvendor ──────────────────────────────────────────────────────────────────

/// Check /sys/class/dmi/id/* vendor fields.
pub fn cvendor() -> bool {
    static PATHS: &[(&str, &[(&str, VMBrand)])] = &[
        ("/sys/class/dmi/id/sys_vendor", &[
            ("QEMU",         VMBrand::QEMU),
            ("VMware",       VMBrand::VMware),
            ("VirtualBox",   VMBrand::VBox),
            ("innotek GmbH", VMBrand::VBox),
            ("Xen",          VMBrand::Xen),
            ("Microsoft",    VMBrand::HyperV),
            ("KVM",          VMBrand::KVM),
            ("Parallels",    VMBrand::Parallels),
            ("OpenStack",    VMBrand::OpenStack),
            ("Google",       VMBrand::GCE),
            ("Amazon",       VMBrand::AWSNitro),
            ("bhyve",        VMBrand::Bhyve),
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

// ── qemu_fw_cfg ──────────────────────────────────────────────────────────────

/// Check for the QEMU fw_cfg device.
pub fn qemu_fw_cfg() -> bool {
    util::exists("/sys/firmware/qemu_fw_cfg") || util::exists("/dev/mem")
        && util::file_contains("/sys/firmware/qemu_fw_cfg/by_name/opt/qemu_fw_cfg_version/raw", "")
}

// ── systemd ───────────────────────────────────────────────────────────────────

/// Check systemd virtualization detection result.
pub fn systemd() -> bool {
    if let Some(v) = util::read_file("/run/systemd/detect-virt") {
        let v = v.trim();
        return v != "none" && !v.is_empty();
    }
    // Try running systemd-detect-virt
    if let Ok(out) = std::process::Command::new("systemd-detect-virt").output() {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        return s.trim() != "none" && !s.trim().is_empty() && out.status.success();
    }
    false
}

// ── ctype ─────────────────────────────────────────────────────────────────────

/// Check /proc/cpuinfo for VM hypervisor flag.
pub fn ctype() -> bool {
    if let Some(cpuinfo) = util::read_file("/proc/cpuinfo") {
        return cpuinfo.contains("hypervisor");
    }
    false
}

// ── dockerenv ─────────────────────────────────────────────────────────────────

/// Check for Docker environment files.
pub fn dockerenv() -> bool {
    if util::exists("/.dockerenv") {
        add_brand_score(VMBrand::Docker, 0);
        return true;
    }
    if util::exists("/.dockerinit") {
        add_brand_score(VMBrand::Docker, 0);
        return true;
    }
    false
}

// ── dmidecode ─────────────────────────────────────────────────────────────────

/// Run dmidecode and check output for VM strings.
pub fn dmidecode() -> bool {
    if let Ok(out) = std::process::Command::new("dmidecode").arg("-t").arg("system").output() {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        static VM_KW: &[(&str, VMBrand)] = &[
            ("virtualbox",   VMBrand::VBox),
            ("vmware",       VMBrand::VMware),
            ("qemu",         VMBrand::QEMU),
            ("xen",          VMBrand::Xen),
            ("kvm",          VMBrand::KVM),
            ("bochs",        VMBrand::Bochs),
            ("microsoft",    VMBrand::HyperV),
            ("parallels",    VMBrand::Parallels),
        ];
        for &(kw, brand) in VM_KW {
            if s.contains(kw) {
                add_brand_score(brand, 0);
                return true;
            }
        }
    }
    false
}

// ── dmesg ─────────────────────────────────────────────────────────────────────

/// Check dmesg output for hypervisor messages.
pub fn dmesg() -> bool {
    if let Ok(out) = std::process::Command::new("dmesg").output() {
        let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
        static KW: &[(&str, VMBrand)] = &[
            ("hypervisor",      VMBrand::Invalid),
            ("vmware",          VMBrand::VMware),
            ("virtualbox",      VMBrand::VBox),
            ("kvm",             VMBrand::KVM),
            ("xen",             VMBrand::Xen),
            ("virt",            VMBrand::Invalid),
            ("paravirt",        VMBrand::KVM),
            ("hv_vmbus",        VMBrand::HyperV),
        ];
        for &(kw, brand) in KW {
            if s.contains(kw) {
                if brand != VMBrand::Invalid {
                    add_brand_score(brand, 0);
                }
                return true;
            }
        }
    }
    false
}

// ── hwmon ─────────────────────────────────────────────────────────────────────

/// VMs typically have no hardware monitoring sensors.
pub fn hwmon() -> bool {
    if let Ok(rd) = std::fs::read_dir("/sys/class/hwmon") {
        return rd.count() == 0;
    }
    true // If hwmon doesn't exist at all → VM likely
}

// ── linux_user_host ───────────────────────────────────────────────────────────

/// Check /etc/hostname and username for sandbox-typical values.
pub fn linux_user_host() -> bool {
    static VM_HOSTNAMES: &[&str] = &[
        "sandbox", "cuckoo", "malware", "analysis", "lab",
        "honeypot", "box", "win7vm", "vm-",
    ];

    let hostname = util::read_file("/etc/hostname").unwrap_or_default();
    let lower = hostname.to_lowercase();
    for kw in VM_HOSTNAMES {
        if lower.contains(kw) {
            return true;
        }
    }
    false
}

// ── vmware_iomem ──────────────────────────────────────────────────────────────

pub fn vmware_iomem() -> bool {
    util::file_contains("/proc/iomem", "VMware")
}

// ── vmware_ioports ────────────────────────────────────────────────────────────

pub fn vmware_ioports() -> bool {
    util::file_contains("/proc/ioports", "VMware")
}

// ── vmware_scsi ───────────────────────────────────────────────────────────────

pub fn vmware_scsi() -> bool {
    util::file_contains("/proc/scsi/scsi", "VMware")
}

// ── vmware_dmesg ──────────────────────────────────────────────────────────────

pub fn vmware_dmesg() -> bool {
    if let Ok(out) = std::process::Command::new("dmesg").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        return s.contains("VMware") || s.contains("VMWARE");
    }
    false
}

// ── qemu_virtual_dmi ─────────────────────────────────────────────────────────

pub fn qemu_virtual_dmi() -> bool {
    util::file_contains("/sys/firmware/dmi/tables/DMI", "QEMU")
        || util::file_contains("/sys/class/dmi/id/bios_vendor", "QEMU")
}

// ── qemu_usb ─────────────────────────────────────────────────────────────────

pub fn qemu_usb() -> bool {
    if let Ok(rd) = std::fs::read_dir("/sys/bus/usb/devices") {
        for entry in rd.flatten() {
            let idv = entry.path().join("idVendor");
            if let Ok(v) = std::fs::read_to_string(&idv) {
                if v.trim() == "1234" {
                    // QEMU USB vendor
                    add_brand_score(VMBrand::QEMU, 0);
                    return true;
                }
            }
        }
    }
    false
}

// ── hypervisor_dir ────────────────────────────────────────────────────────────

pub fn hypervisor_dir() -> bool {
    static DIRS: &[(&str, VMBrand)] = &[
        ("/proc/vz",             VMBrand::OpenVZ),
        ("/proc/bc",             VMBrand::OpenVZ),
        ("/proc/xen",            VMBrand::Xen),
        ("/proc/xenolinux-banner", VMBrand::Xen),
    ];
    for &(path, brand) in DIRS {
        if util::exists(path) {
            add_brand_score(brand, 0);
            return true;
        }
    }
    false
}

// ── uml_cpu ───────────────────────────────────────────────────────────────────

pub fn uml_cpu() -> bool {
    if let Some(cpuinfo) = util::read_file("/proc/cpuinfo") {
        if cpuinfo.contains("User Mode Linux") || cpuinfo.contains("UML") {
            add_brand_score(VMBrand::UML, 0);
            return true;
        }
    }
    false
}

// ── vbox_module ───────────────────────────────────────────────────────────────

pub fn vbox_module() -> bool {
    if let Some(mods) = util::read_file("/proc/modules") {
        let vm_mods = ["vboxdrv", "vboxguest", "vboxpci", "vboxnetflt", "vboxnetadp"];
        for m in &vm_mods {
            if mods.contains(m) {
                add_brand_score(VMBrand::VBox, 0);
                return true;
            }
        }
    }
    false
}

// ── sysinfo_proc ─────────────────────────────────────────────────────────────

pub fn sysinfo_proc() -> bool {
    util::file_contains("/proc/sysinfo", "VM00") || util::file_contains("/proc/sysinfo", "z/VM")
}

// ── dmi_scan ─────────────────────────────────────────────────────────────────

pub fn dmi_scan() -> bool {
    cvendor() // reuses the same DMI scan logic
}

// ── podman_file ───────────────────────────────────────────────────────────────

pub fn podman_file() -> bool {
    if util::exists("/run/.containerenv") {
        add_brand_score(VMBrand::Podman, 0);
        return true;
    }
    false
}

// ── wsl_proc ─────────────────────────────────────────────────────────────────

pub fn wsl_proc() -> bool {
    if util::file_contains("/proc/version", "Microsoft")
        || util::file_contains("/proc/version", "WSL")
    {
        add_brand_score(VMBrand::WSL, 0);
        return true;
    }
    if util::exists("/proc/sys/fs/binfmt_misc/WSLInterop") {
        add_brand_score(VMBrand::WSL, 0);
        return true;
    }
    false
}

// ── file_access_history ───────────────────────────────────────────────────────

pub fn file_access_history() -> bool {
    // Check recent file access history for sandbox indicators
    util::exists("/root/.bash_history") && {
        util::read_file("/root/.bash_history")
            .map(|h| h.lines().count() == 0)
            .unwrap_or(false)
    }
}

// ── mac ───────────────────────────────────────────────────────────────────────

pub fn mac() -> bool {
    // Check MAC address OUIs for known VM vendors
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for entry in rd.flatten() {
            let mac_path = entry.path().join("address");
            if let Ok(addr) = std::fs::read_to_string(&mac_path) {
                let addr = addr.trim().to_lowercase();
                // VMware: 00:0c:29, 00:50:56, 00:05:69
                // VirtualBox: 08:00:27
                // QEMU: 52:54:00
                // Parallels: 00:1c:42
                // Hyper-V: 00:15:5d
                static VM_MACS: &[(&str, VMBrand)] = &[
                    ("00:0c:29", VMBrand::VMware),
                    ("00:50:56", VMBrand::VMware),
                    ("00:05:69", VMBrand::VMware),
                    ("08:00:27", VMBrand::VBox),
                    ("52:54:00", VMBrand::QEMUKVM),
                    ("00:1c:42", VMBrand::Parallels),
                    ("00:15:5d", VMBrand::HyperV),
                ];
                for &(prefix, brand) in VM_MACS {
                    if addr.starts_with(prefix) {
                        add_brand_score(brand, 0);
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ── nsjail_pid ────────────────────────────────────────────────────────────────

pub fn nsjail_pid() -> bool {
    // nsjail sets PID namespace so PID 1 is not init/systemd
    if let Some(comm) = util::read_file("/proc/1/comm") {
        let c = comm.trim();
        if c != "systemd" && c != "init" && c != "upstart" && c != "svscan" {
            // Check if we're in a nested PID namespace
            if util::file_contains("/proc/1/environ", "NSJAIL") {
                add_brand_score(VMBrand::NSJail, 0);
                return true;
            }
        }
    }
    false
}

// ── bluestacks_folders ────────────────────────────────────────────────────────

pub fn bluestacks_folders() -> bool {
    static PATHS: &[&str] = &[
        "/sdcard",
        "/data/app",
        "/system/priv-app",
    ];
    // BlueStacks specific: all three exist together
    let count = PATHS.iter().filter(|p| util::exists(p)).count();
    if count >= 2 {
        add_brand_score(VMBrand::BlueStacks, 0);
        return true;
    }
    false
}

// ── amd_sev_msr ──────────────────────────────────────────────────────────────

pub fn amd_sev_msr() -> bool {
    use crate::cpu::{cpuid, is_amd, is_leaf_supported};
    if !is_amd() {
        return false;
    }

    // CRITICAL correctness check: CPUID 0x8000001F EAX bits are *capability*
    // bits that say the hardware SUPPORTS SEV/SEV-ES/SEV-SNP, **not** that the
    // current execution is running inside an SEV-protected guest VM.
    //
    // On a bare-metal AMD EPYC / Ryzen Pro machine with SEV firmware support,
    // these bits will be set even though no VM is present – which would produce
    // a false positive.
    //
    // Mitigation: also require the hypervisor-present bit (CPUID leaf 1 ECX
    // bit 31) to be set.  On bare metal this bit is always 0; it is only set
    // when the processor is running as a guest under a hypervisor.  Combined
    // with the SEV capability bits this gives a reliable "inside an SEV guest"
    // signal without ring-0 MSR access.
    let leaf1 = cpuid(1, 0);
    let hypervisor_present = (leaf1.ecx >> 31) & 1 != 0;
    if !hypervisor_present {
        return false;
    }

    if is_leaf_supported(0x8000_001F) {
        let r = cpuid(0x8000_001F, 0);
        let sev_snp = (r.eax >> 4) & 1 != 0;
        let sev_es = (r.eax >> 3) & 1 != 0;
        let sev = r.eax & 1 != 0;
        if sev_snp {
            add_brand_score(VMBrand::AMDSEVsnp, 0);
            return true;
        } else if sev_es {
            add_brand_score(VMBrand::AMDSEVes, 0);
            return true;
        } else if sev {
            add_brand_score(VMBrand::AMDSEV, 0);
            return true;
        }
    }
    false
}

// ── temperature ───────────────────────────────────────────────────────────────

/// VMs usually have no thermal sensors.
pub fn temperature() -> bool {
    if let Ok(rd) = std::fs::read_dir("/sys/class/thermal") {
        return rd.count() == 0;
    }
    true
}

// ── battery ───────────────────────────────────────────────────────────────────

/// VMs almost never expose a real battery.  `/sys/class/power_supply/` will
/// be empty or contain only an AC-adapter entry on virtualised systems, while
/// laptops and some desktops enumerate at least one `BAT*` device here.
///
/// NOTE: This technique is intentionally NOT registered in the technique
/// table (`core.rs`).  It is implemented for research / future use only.
/// On servers, cloud instances, and desktop PCs there is also no battery,
/// so the signal is unreliable on its own outside a client-device context.
#[allow(dead_code)]
pub fn battery() -> bool {
    let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") else {
        // Directory missing → no power-supply subsystem exposed → VM likely
        return true;
    };

    let has_battery = rd.flatten().any(|e| {
        let name = e.file_name();
        let s = name.to_string_lossy();
        // Battery entries are named BAT0, BAT1, battery, etc.
        s.to_ascii_uppercase().starts_with("BAT")
    });

    !has_battery
}

// ── processes ─────────────────────────────────────────────────────────────────

/// Check running processes for known VM guest agent names.
pub fn processes() -> bool {
    static VM_PROCS: &[(&str, VMBrand)] = &[
        ("vmtoolsd",     VMBrand::VMware),
        ("vmwaretray",   VMBrand::VMware),
        ("vmwareuser",   VMBrand::VMware),
        ("VBoxService",  VMBrand::VBox),
        ("VBoxClient",   VMBrand::VBox),
        ("prl_tools",    VMBrand::Parallels),
        ("qemu-ga",      VMBrand::QEMU),
        ("cuckoo",       VMBrand::Cuckoo),
    ];

    if let Ok(rd) = std::fs::read_dir("/proc") {
        for entry in rd.flatten() {
            let comm = entry.path().join("comm");
            if let Ok(name) = std::fs::read_to_string(&comm) {
                let name = name.trim().to_lowercase();
                for &(proc_name, brand) in VM_PROCS {
                    if name.contains(&proc_name.to_lowercase()) {
                        add_brand_score(brand, 0);
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ── thread_count ─────────────────────────────────────────────────────────────

pub fn thread_count() -> bool {
    crate::techniques::cross::thread_count()
}
