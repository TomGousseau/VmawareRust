//! Detection engine – mirrors vmaware_core.c.
//!
//! Contains the technique dispatch table, brand scoreboard, and the main
//! `run_all` / `detect` / `get_percentage` / `get_brand` functions.

use crate::memo;
use crate::techniques;
use crate::types::{Flagset, Technique, VMBrand, HIGH_THRESHOLD_SCORE, THRESHOLD_SCORE};
use crate::util;

use std::sync::Mutex;

// ── Brand scoreboard ──────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct BrandEntry {
    brand: VMBrand,
    score: u32,
}

static BRAND_SCOREBOARD: Mutex<Vec<BrandEntry>> = Mutex::new(Vec::new());

/// Add a brand to the scoreboard (score unchanged at 0 if brand absent).
pub fn add_brand(brand: VMBrand) {
    let mut board = BRAND_SCOREBOARD.lock().unwrap();
    if !board.iter().any(|e| e.brand == brand) {
        board.push(BrandEntry { brand, score: 0 });
    }
}

/// Add `score` points to `brand` in the scoreboard.
pub fn add_brand_score(brand: VMBrand, score: u32) {
    let mut board = BRAND_SCOREBOARD.lock().unwrap();
    if let Some(e) = board.iter_mut().find(|e| e.brand == brand) {
        e.score += score;
    } else {
        board.push(BrandEntry { brand, score });
    }
}

/// Reset the scoreboard and all memo caches.
pub fn reset() {
    BRAND_SCOREBOARD.lock().unwrap().clear();
    memo::reset_all();
}

// ── Technique dispatch table ──────────────────────────────────────────────────

struct TechEntry {
    id: Technique,
    points: u32,
    func: fn() -> bool,
}

macro_rules! entry {
    ($id:expr, $pts:expr, $fn:expr) => {
        TechEntry { id: $id, points: $pts, func: $fn }
    };
}

fn build_table() -> Vec<TechEntry> {
    use techniques::cross::*;
#[cfg(windows)]
        use techniques::win::*;

    #[cfg(target_os = "linux")]
    use techniques::linux::*;

    vec![
        // ── Cross-platform CPUID techniques ──────────────────────────────────
        entry!(Technique::Vmid,           100, vmid),
        entry!(Technique::CpuBrand,        95, cpu_brand),
        entry!(Technique::HypervisorBit,  100, hypervisor_bit),
        entry!(Technique::HypervisorStr,  100, hypervisor_str),
        entry!(Technique::BochsCpu,       100, bochs_cpu),
        entry!(Technique::Timer,          100, timer),
        entry!(Technique::ThreadMismatch,  50, thread_mismatch),
        entry!(Technique::CpuidSignature,  95, cpuid_signature),
        entry!(Technique::KgtSignature,    80, kgt_signature),

        // ── Windows-only techniques ───────────────────────────────────────────
        #[cfg(windows)]
        entry!(Technique::Dll,             45, dll),
        #[cfg(windows)]
        entry!(Technique::Wine,            85, wine),
        #[cfg(windows)]
        entry!(Technique::PowerCapabilities, 35, power_capabilities),
        #[cfg(windows)]
        entry!(Technique::Gamarue,         40, gamarue),
        #[cfg(windows)]
        entry!(Technique::VpcInvalid,      75, vpc_invalid),
        #[cfg(windows)]
        entry!(Technique::VmwareStr,       45, vmware_str),
        #[cfg(windows)]
        entry!(Technique::VmwareBackdoor, 100, vmware_backdoor),
        #[cfg(windows)]
        entry!(Technique::Mutex,           85, mutex),
        #[cfg(windows)]
        entry!(Technique::CuckooDir,       15, cuckoo_dir),
        #[cfg(windows)]
        entry!(Technique::CuckooPipe,      20, cuckoo_pipe),
        #[cfg(windows)]
        entry!(Technique::Display,         35, display),
        #[cfg(windows)]
        entry!(Technique::DeviceString,    35, device_string),
        #[cfg(windows)]
        entry!(Technique::Drivers,         65, drivers),
        #[cfg(windows)]
        entry!(Technique::DiskSerial,      60, disk_serial),
        #[cfg(windows)]
        entry!(Technique::VirtualRegistry, 65, virtual_registry),
        #[cfg(windows)]
        entry!(Technique::Audio,           35, audio),
        #[cfg(windows)]
        entry!(Technique::AcpiSignature,   80, acpi_signature),
        #[cfg(windows)]
        entry!(Technique::Trap,           100, trap),
        #[cfg(windows)]
        entry!(Technique::Ud,             100, ud),
        #[cfg(windows)]
        entry!(Technique::Blockstep,      100, blockstep),
        #[cfg(windows)]
        entry!(Technique::BootLogo,        10, boot_logo),
        #[cfg(windows)]
        entry!(Technique::KernelObjects,   50, kernel_objects),
        #[cfg(windows)]
        entry!(Technique::Nvram,          100, nvram),
        #[cfg(windows)]
        entry!(Technique::Edid,            55, edid),
        #[cfg(windows)]
        entry!(Technique::Clock,           65, clock),
        #[cfg(windows)]
        entry!(Technique::Handles,         25, handles),
        #[cfg(windows)]
        entry!(Technique::VirtualProcessors, 30, virtual_processors),
        #[cfg(windows)]
        entry!(Technique::HypervisorQuery, 65, hypervisor_query),
        #[cfg(windows)]
        entry!(Technique::Ivshmem,         65, ivshmem),
        #[cfg(windows)]
        entry!(Technique::GpuCapabilities, 35, gpu_capabilities),
        #[cfg(windows)]
        entry!(Technique::CpuHeuristic,    30, cpu_heuristic),
        #[cfg(windows)]
        entry!(Technique::DbvmHypercall,  100, dbvm_hypercall),
        #[cfg(windows)]
        entry!(Technique::Msr,             65, msr),
        #[cfg(windows)]
        entry!(Technique::KvmInterception, 65, kvm_interception),
        #[cfg(windows)]
        entry!(Technique::Breakpoint,      65, breakpoint),

        // ── Linux + Windows techniques ────────────────────────────────────────
        #[cfg(any(windows, target_os = "linux"))]
        entry!(Technique::SystemRegisters, 35, system_registers),
        #[cfg(any(windows, target_os = "linux"))]
        entry!(Technique::Firmware,        80, firmware),
        #[cfg(any(windows, target_os = "linux"))]
        entry!(Technique::Devices,         35, devices),
        #[cfg(any(windows, target_os = "linux"))]
        entry!(Technique::Azure,           25, azure),

        // ── Linux-only techniques ─────────────────────────────────────────────
        #[cfg(target_os = "linux")]
        entry!(Technique::SmbiosVmBit,     35, smbios_vm_bit),
        #[cfg(target_os = "linux")]
        entry!(Technique::Kmsg,            30, kmsg),
        #[cfg(target_os = "linux")]
        entry!(Technique::Cvendor,         65, cvendor),
        #[cfg(target_os = "linux")]
        entry!(Technique::QemuFwCfg,       40, qemu_fw_cfg),
        #[cfg(target_os = "linux")]
        entry!(Technique::Systemd,         30, systemd),
        #[cfg(target_os = "linux")]
        entry!(Technique::Ctype,           25, ctype),
        #[cfg(target_os = "linux")]
        entry!(Technique::Dockerenv,       95, dockerenv),
        #[cfg(target_os = "linux")]
        entry!(Technique::Dmidecode,       55, dmidecode),
        #[cfg(target_os = "linux")]
        entry!(Technique::Dmesg,           65, dmesg),
        #[cfg(target_os = "linux")]
        entry!(Technique::Hwmon,           25, hwmon),
        #[cfg(target_os = "linux")]
        entry!(Technique::LinuxUserHost,   35, linux_user_host),
        #[cfg(target_os = "linux")]
        entry!(Technique::VmwareIomem,     65, vmware_iomem),
        #[cfg(target_os = "linux")]
        entry!(Technique::VmwareIoports,   65, vmware_ioports),
        #[cfg(target_os = "linux")]
        entry!(Technique::VmwareScsi,      40, vmware_scsi),
        #[cfg(target_os = "linux")]
        entry!(Technique::VmwareDmesg,     50, vmware_dmesg),
        #[cfg(target_os = "linux")]
        entry!(Technique::QemuVirtualDmi,  40, qemu_virtual_dmi),
        #[cfg(target_os = "linux")]
        entry!(Technique::QemuUsb,         20, qemu_usb),
        #[cfg(target_os = "linux")]
        entry!(Technique::HypervisorDir,   40, hypervisor_dir),
        #[cfg(target_os = "linux")]
        entry!(Technique::UmlCpu,          80, uml_cpu),
        #[cfg(target_os = "linux")]
        entry!(Technique::VboxModule,      65, vbox_module),
        #[cfg(target_os = "linux")]
        entry!(Technique::SysinfoProc,     25, sysinfo_proc),
        #[cfg(target_os = "linux")]
        entry!(Technique::DmiScan,         55, dmi_scan),
        #[cfg(target_os = "linux")]
        entry!(Technique::PodmanFile,      95, podman_file),
        #[cfg(target_os = "linux")]
        entry!(Technique::WslProc,         95, wsl_proc),
        #[cfg(target_os = "linux")]
        entry!(Technique::FileAccessHistory, 15, file_access_history),
        #[cfg(target_os = "linux")]
        entry!(Technique::Mac,             30, mac),
        #[cfg(target_os = "linux")]
        entry!(Technique::NsjailPid,       95, nsjail_pid),
        #[cfg(target_os = "linux")]
        entry!(Technique::BluestacksFolders, 60, bluestacks_folders),
        #[cfg(target_os = "linux")]
        entry!(Technique::AmdSevMsr,       95, amd_sev_msr),
        #[cfg(target_os = "linux")]
        entry!(Technique::Temperature,     25, temperature),
        #[cfg(target_os = "linux")]
        entry!(Technique::Processes,       30, processes),
        // ThreadCount: Linux + macOS
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        entry!(Technique::ThreadCount,     35, techniques::cross::thread_count),
    ]
}

// ── run_all / detect / percentage / brand ─────────────────────────────────────

/// Run all enabled techniques (those set in `flags`).
/// Returns the accumulated VM score.
/// If `shortcut` is true, stops early once THRESHOLD_SCORE is reached.
pub fn run_all(flags: Flagset, shortcut: bool) -> u32 {
    let table = build_table();
    let mut score: u32 = 0;

    for entry in &table {
        if !flags.is_empty() && !flags.is_set(entry.id) {
            continue;
        }

        // Skip unsupported platform techniques
        if util::is_unsupported(entry.id) {
            continue;
        }

        let tech_id = entry.id as u8;

        // Return cached result if available
        if let Some(cached) = memo::cache_fetch(tech_id) {
            if cached.result {
                score += cached.points;
            }
            if shortcut && score >= THRESHOLD_SCORE {
                return score;
            }
            continue;
        }

        // Run the technique
        let result = (entry.func)();
        let pts = if result { entry.points } else { 0 };
        score += pts;

        // Determine the brand from scoreboard (take highest)
        let brand = best_brand();
        memo::cache_store(tech_id, result, entry.points, brand);

        if shortcut && score >= THRESHOLD_SCORE {
            return score;
        }
    }

    score
}

/// Returns true if the VM score meets or exceeds THRESHOLD_SCORE.
pub fn detect(flags: Flagset) -> bool {
    run_all(flags, true) >= THRESHOLD_SCORE
}

/// Returns the VM confidence percentage (0–100, clamped).
pub fn get_percentage(flags: Flagset) -> u8 {
    let score = run_all(flags, false);
    let pct = (score * 100) / HIGH_THRESHOLD_SCORE;
    pct.min(100) as u8
}

/// Returns the highest-scoring VM brand from the scoreboard.
pub fn get_brand(flags: Flagset) -> VMBrand {
    run_all(flags, false);
    best_brand()
}

fn best_brand() -> VMBrand {
    let board = BRAND_SCOREBOARD.lock().unwrap();
    board
        .iter()
        .max_by_key(|e| e.score)
        .map(|e| e.brand)
        .unwrap_or(VMBrand::Invalid)
}

/// Returns the list of all brands that scored > 0.
pub fn get_detected_brands(flags: Flagset) -> Vec<VMBrand> {
    run_all(flags, false);
    let board = BRAND_SCOREBOARD.lock().unwrap();
    board
        .iter()
        .filter(|e| e.score > 0)
        .map(|e| e.brand)
        .collect()
}

/// Returns the number of techniques that returned true.
pub fn detected_technique_count(flags: Flagset) -> usize {
    run_all(flags, false);
    // Count cached results that are true
    let mut count = 0usize;
    for id in 0..Technique::COUNT as u8 {
        if let Some(r) = memo::cache_fetch(id) {
            if r.result {
                count += 1;
            }
        }
    }
    count
}
