//! Utility helpers – mirrors vmaware_util.c.
//!
//! Platform checks, file helpers, admin detection, hyper-x classification,
//! thread counting and string utilities.

use crate::types::{HyperXState, Technique};
use crate::{cpu, memo};

// ── Platform checks ───────────────────────────────────────────────────────────

/// Returns true when the given technique is unsupported on the current platform
/// (so the caller should skip it without counting it as a VM indicator).
pub fn is_unsupported(tech: Technique) -> bool {
    use Technique::*;

    #[cfg(windows)]
    {
        // Linux / macOS only
        const LINUX_ONLY: &[Technique] = &[
            SmbiosVmBit, Kmsg, Cvendor, QemuFwCfg, Systemd, Ctype, Dockerenv,
            Dmidecode, Dmesg, Hwmon, LinuxUserHost, VmwareIomem, VmwareIoports,
            VmwareScsi, VmwareDmesg, QemuVirtualDmi, QemuUsb, HypervisorDir,
            UmlCpu, VboxModule, SysinfoProc, DmiScan, PodmanFile, WslProc,
            FileAccessHistory, Mac, NsjailPid, BluestacksFolders, AmdSevMsr,
            Temperature, Processes, ThreadCount,
            MacMemsize, MacIokit, MacSip, IoregGrep, Hwmodel, MacSys,
        ];
        return LINUX_ONLY.contains(&tech);
    }

    #[cfg(all(target_os = "linux", not(windows)))]
    {
        // Windows-only
        const WIN_ONLY: &[Technique] = &[
            GpuCapabilities, AcpiSignature, PowerCapabilities, DiskSerial,
            Ivshmem, Drivers, Handles, VirtualProcessors, HypervisorQuery,
            Audio, Display, Dll, VmwareBackdoor, Wine, VirtualRegistry,
            Mutex, DeviceString, VpcInvalid, VmwareStr, Gamarue, CuckooDir,
            CuckooPipe, BootLogo, Trap, Ud, Blockstep, DbvmHypercall,
            KernelObjects, Nvram, Edid, CpuHeuristic, Clock, Msr,
            KvmInterception, Breakpoint,
            MacMemsize, MacIokit, MacSip, IoregGrep, Hwmodel, MacSys,
        ];
        return WIN_ONLY.contains(&tech);
    }

    #[cfg(target_os = "macos")]
    {
        const MACOS_EXCL: &[Technique] = &[
            GpuCapabilities, AcpiSignature, PowerCapabilities, DiskSerial,
            Ivshmem, Drivers, Handles, VirtualProcessors, HypervisorQuery,
            Audio, Display, Dll, VmwareBackdoor, Wine, VirtualRegistry,
            Mutex, DeviceString, VpcInvalid, VmwareStr, Gamarue, CuckooDir,
            CuckooPipe, BootLogo, Trap, Ud, Blockstep, DbvmHypercall,
            KernelObjects, Nvram, Edid, CpuHeuristic, Clock, Msr,
            KvmInterception, Breakpoint,
            SmbiosVmBit, Kmsg, Cvendor, QemuFwCfg, Systemd, Ctype, Dockerenv,
            Dmidecode, Dmesg, Hwmon, LinuxUserHost, VmwareIomem, VmwareIoports,
            VmwareScsi, VmwareDmesg, QemuVirtualDmi, QemuUsb, HypervisorDir,
            UmlCpu, VboxModule, SysinfoProc, DmiScan, PodmanFile, WslProc,
            FileAccessHistory, Mac, NsjailPid, BluestacksFolders, AmdSevMsr,
            Temperature, Processes,
        ];
        return MACOS_EXCL.contains(&tech);
    }

    // Fallback for unknown platforms (cross-platform only)
    #[allow(unreachable_code)]
    {
        let cross = [
            Technique::HypervisorBit, Technique::Vmid, Technique::ThreadMismatch,
            Technique::Timer, Technique::CpuBrand, Technique::HypervisorStr,
            Technique::CpuidSignature, Technique::BochsCpu, Technique::KgtSignature,
        ];
        !cross.contains(&tech)
    }
}

// ── File helpers ──────────────────────────────────────────────────────────────

/// Returns true when `path` exists on the filesystem.
pub fn exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// Reads a file to a String. Returns `None` on any error.
pub fn read_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Returns true when a file exists and its contents contain `needle`.
pub fn file_contains(path: &str, needle: &str) -> bool {
    read_file(path).map(|c| c.contains(needle)).unwrap_or(false)
}

// ── Admin / elevated privilege check ─────────────────────────────────────────

/// Returns true if the current process has administrator / root privileges.
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};

        unsafe {
            let mut token: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    #[cfg(not(windows))]
    {
        // POSIX: check for UID 0
        libc_uid() == 0
    }
}

#[cfg(not(windows))]
fn libc_uid() -> u32 {
    // Use std::os::unix equivalent
    #[cfg(unix)]
    {
        // SAFETY: getuid() is always safe to call
        extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() }
    }
    #[cfg(not(unix))]
    {
        1 // assume non-root on unknown platforms
    }
}

// ── SMT / logical CPU count ───────────────────────────────────────────────────

/// Return the number of logical processors (hardware threads) visible to the OS.
pub fn get_logical_cpu_count() -> u32 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::GetSystemInfo;
        use windows_sys::Win32::System::SystemInformation::SYSTEM_INFO;
        unsafe {
            let mut si = std::mem::zeroed::<SYSTEM_INFO>();
            GetSystemInfo(&mut si);
            si.dwNumberOfProcessors
        }
    }

    #[cfg(not(windows))]
    {
        // Use std::thread::available_parallelism as a portable fallback
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
    }
}

// ── HyperX detection ─────────────────────────────────────────────────────────

/// Classify the current execution environment as real VM, artifact VM,
/// enlightened hypervisor host, or unknown.
pub fn hyper_x() -> HyperXState {
    // Return cached value if available
    if let Some(s) = memo::get_hyperx_state() {
        return s;
    }

    let state = hyper_x_inner();
    memo::set_hyperx_state(state);
    state
}

fn hyper_x_inner() -> HyperXState {
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    return HyperXState::Unknown;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        use crate::cpu::{cpuid, is_leaf_supported};

        // 1. Check hypervisor bit (CPUID 1 ECX bit 31)
        let ecx1 = cpuid(1, 0).ecx;
        let hypervisor_bit = (ecx1 >> 31) & 1 != 0;

        if !hypervisor_bit {
            return HyperXState::Unknown;
        }

        // 2. Check if root partition (Hyper-V enlightened host)
        //    CPUID 0x40000003, EBX bit 0 = "CreatePartitions" privilege.
        if is_leaf_supported(0x4000_0003) {
            let ebx = cpuid(0x4000_0003, 0).ebx;
            if ebx & 1 != 0 {
                return HyperXState::Enlightenment;
            }
        }

        // 3. Distinguish real VM vs artifact by max hypervisor leaf
        let max_leaf = cpuid(0x4000_0000, 0).eax;

        if max_leaf >= 0x4000_0005 {
            // Rich leaf set → more likely a full VM
            HyperXState::RealVM
        } else {
            HyperXState::ArtifactVM
        }
    }
}

// ── BIOS / manufacturer / model helpers ───────────────────────────────────────

/// Return (manufacturer, model) from the hardware description registry (Windows)
/// or DMI/SMBIOS on Linux.
pub fn get_manufacturer_model() -> (String, String) {
    // Return cached value
    if let Some(info) = memo::get_bios_info() {
        return (info.manufacturer, info.model);
    }

    let result = get_manufacturer_model_inner();
    memo::set_bios_info(memo::BiosInfo {
        manufacturer: result.0.clone(),
        model: result.1.clone(),
    });
    result
}

#[cfg(windows)]
fn get_manufacturer_model_inner() -> (String, String) {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("HARDWARE\\DESCRIPTION\\System\\BIOS") {
        let mfr: String = key.get_value("SystemManufacturer").unwrap_or_default();
        let mdl: String = key.get_value("SystemProductName").unwrap_or_default();
        return (mfr, mdl);
    }
    (String::new(), String::new())
}

#[cfg(not(windows))]
fn get_manufacturer_model_inner() -> (String, String) {
    let mfr = read_file("/sys/class/dmi/id/sys_vendor")
        .unwrap_or_default()
        .trim()
        .to_string();
    let mdl = read_file("/sys/class/dmi/id/product_name")
        .unwrap_or_default()
        .trim()
        .to_string();
    (mfr, mdl)
}

// ── String helpers ────────────────────────────────────────────────────────────

/// Case-insensitive substring search.
pub fn str_contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// CRC32C (software) of a byte slice.
pub fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ── SMT detection ─────────────────────────────────────────────────────────────

/// Returns true when SMT (Hyper-Threading / simultaneous multithreading) is
/// enabled on the current x86 processor.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn is_smt_enabled() -> bool {
    use cpu::{cpuid, is_leaf_supported};
    if !is_leaf_supported(0x0B) {
        return false;
    }
    // Leaf 0x0B, subleaf 0 reports SMT level thread count
    let r = cpuid(0x0B, 0);
    let level_type = (r.ecx >> 8) & 0xFF;
    let threads_at_level = r.ebx & 0xFFFF;
    // level_type == 1 is SMT level
    level_type == 1 && threads_at_level > 1
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn is_smt_enabled() -> bool {
    false
}
