//! Windows-specific VM detection techniques.
//!
//! Mirrors vmaware_win.c: wine, dll, power_capabilities, vmware_backdoor,
//! mutex, virtual_registry, gamarue, vpc_invalid, vmware_str, cuckoo_dir,
//! cuckoo_pipe, display, device_string, drivers, disk_serial, ivshmem,
//! gpu_capabilities, handles, virtual_processors, hypervisor_query, audio,
//! acpi_signature, trap, ud, blockstep, dbvm_hypercall, boot_logo,
//! kernel_objects, nvram, edid, cpu_heuristic, clock, msr, kvm_interception,
//! breakpoint, azure, firmware, devices, system_registers.

#![cfg(windows)]

use crate::core::{add_brand, add_brand_score};
use crate::types::VMBrand;
use crate::util;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, OPEN_EXISTING,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

// ── Helper macros ─────────────────────────────────────────────────────────────

macro_rules! cstr {
    ($s:expr) => {
        concat!($s, "\0").as_ptr()
    };
}

// ── Spoofed NT wrappers ───────────────────────────────────────────────────────
//
// On x86-64 Windows these call `NtQuerySystemInformation` via a direct
// `syscall` instruction, completely bypassing the ntdll.dll trampoline that
// AV/EDR products (including Windows Defender ATP) hook in userland.
// On other Windows architectures the implementation falls back to the standard
// GetProcAddress path, which is functionally identical but hookable.

/// NtQuerySystemInformation wrapper – Hell's Gate spoofed on x86-64.
#[inline]
unsafe fn nt_qsi(class: u32, buf: *mut u8, len: u32, ret_len: *mut u32) -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        return crate::syscall::nt_query_system_information(class, buf, len, ret_len);
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 {
            return -1;
        }
        type F = unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32;
        match GetProcAddress(ntdll, b"NtQuerySystemInformation\0".as_ptr()) {
            Some(f) => {
                let f: F = std::mem::transmute(f);
                f(class, buf, len, ret_len)
            }
            None => -1,
        }
    }
}

/// Open a device path and immediately close it; returns true on success.
unsafe fn try_open_device(path: &[u8]) -> bool {
    let h = CreateFileA(
        path.as_ptr(),
        0, // no access needed
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        std::ptr::null(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0,
    );
    if h != INVALID_HANDLE_VALUE && h != 0 {
        CloseHandle(h);
        true
    } else {
        false
    }
}

// ── wine ──────────────────────────────────────────────────────────────────────

/// Detect Wine by looking for the "wine_get_version" export in ntdll.
pub fn wine() -> bool {
    unsafe {
        let ntdll = GetModuleHandleA(cstr!("ntdll.dll") as *const u8);
        if ntdll == 0 {
            return false;
        }
        let proc = GetProcAddress(ntdll, cstr!("wine_get_version") as *const u8);
        if proc.is_some() {
            add_brand_score(VMBrand::Wine, 0);
            return true;
        }
        false
    }
}

// ── dll ───────────────────────────────────────────────────────────────────────

/// Check for VM guest library DLLs loaded in the process.
pub fn dll() -> bool {
    static DLLS: &[(&[u8], VMBrand)] = &[
        (b"vmGuestLib.dll\0",   VMBrand::VMware),
        (b"vmhgfs.dll\0",       VMBrand::VMware),
        (b"vboxmrxnp.dll\0",    VMBrand::VBox),
        (b"vboxogl.dll\0",      VMBrand::VBox),
        (b"vboxdisp.dll\0",     VMBrand::VBox),
        (b"sbiedll.dll\0",      VMBrand::Sandboxie),
        (b"dbghelp.dll\0",      VMBrand::Invalid),  // skip – common
        (b"api_log.dll\0",      VMBrand::CWSandbox),
        (b"dir_watch.dll\0",    VMBrand::CWSandbox),
        (b"pstorec.dll\0",      VMBrand::ThreatExpert),
        (b"vmcheck.dll\0",      VMBrand::VPC),
        (b"wpespy.dll\0",       VMBrand::Invalid),
        (b"SbieDll.dll\0",      VMBrand::Sandboxie),
        (b"cuckoomon.dll\0",    VMBrand::Cuckoo),
    ];

    unsafe {
        for &(dll, brand) in DLLS {
            if brand == VMBrand::Invalid {
                continue;
            }
            let h = GetModuleHandleA(dll.as_ptr());
            if h != 0 {
                add_brand_score(brand, 0);
                return true;
            }
        }
        false
    }
}

// ── power_capabilities ────────────────────────────────────────────────────────

/// VMs often lack S1/S2/S3/S4 power states.
pub fn power_capabilities() -> bool {
    use windows_sys::Win32::System::Power::{
        GetPwrCapabilities, SYSTEM_POWER_CAPABILITIES,
    };

    unsafe {
        let mut caps = std::mem::zeroed::<SYSTEM_POWER_CAPABILITIES>();
        if GetPwrCapabilities(&mut caps) == FALSE {
            return false;
        }
        // If none of S1/S2/S3/S4 are supported → VM
        !caps.SystemS1 && !caps.SystemS2 && !caps.SystemS3 && !caps.SystemS4
    }
}

// ── vmware_backdoor ───────────────────────────────────────────────────────────

/// Test the VMware hypervisor I/O backdoor port (0x5658).
pub fn vmware_backdoor() -> bool {
    #[cfg(not(target_arch = "x86_64"))]
    return false;

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // VMware magic: IN EAX, 0x5658 with EAX=0x564D5868 ('VMXh'), EBX=0, ECX=10
        let mut eax: u32 = 0x564D_5868; // VMXh
        let mut ebx: u32 = 0;
        let mut ecx: u32 = 10; // get-version command
        let mut edx: u32 = 0x5658; // port number

        // We use a try/catch equivalent: attempt and check if we #GP
        // In Rust, we can use a signal handler approach, but for simplicity
        // we catch the result: EBX should be 0x564D5868 on VMware
        let result: u32;
        std::arch::asm!(
            "in eax, dx",
            inout("eax") eax => eax,
            inout("ebx") ebx => ebx,
            inout("ecx") ecx => ecx,
            inout("edx") edx => edx,
            options(nostack),
        );

        if eax == 0x564D_5868 || ebx == 0x564D_5868 {
            add_brand_score(VMBrand::VMware, 0);
            true
        } else {
            false
        }
    }
}

// ── mutex ─────────────────────────────────────────────────────────────────────

/// Check for VM-specific mutex objects.
pub fn mutex() -> bool {
    use windows_sys::Win32::System::Threading::{CreateMutexA, OpenMutexA};
    use windows_sys::Win32::Security::SYNCHRONIZE;

    static MUTEXES: &[(&[u8], VMBrand)] = &[
        (b"VBoxTrayIPC-\0",              VMBrand::VBox),
        (b"VBoxGuest\0",                 VMBrand::VBox),
        (b"MGA_APP_MUTEX\0",             VMBrand::VMware),
        (b"VMWARE_TOOLS_UPGRADE_MUTEX\0", VMBrand::VMware),
        (b"VBEAM_MUTEX\0",               VMBrand::VMware),
        (b"TPAutoConnSvcMutex\0",        VMBrand::VMware),
        (b"cuckoo_signal\0",             VMBrand::Cuckoo),
    ];

    unsafe {
        for &(name, brand) in MUTEXES {
            let h = OpenMutexA(SYNCHRONIZE, FALSE, name.as_ptr());
            if h != 0 {
                CloseHandle(h);
                add_brand_score(brand, 0);
                return true;
            }
        }
        false
    }
}

// ── virtual_registry ──────────────────────────────────────────────────────────

/// Check for VM-specific registry keys.
pub fn virtual_registry() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    static KEYS: &[(&str, VMBrand)] = &[
        (r"SOFTWARE\VMware, Inc.\VMware Tools",         VMBrand::VMware),
        (r"SOFTWARE\VirtualBox Guest Additions",         VMBrand::VBox),
        (r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", VMBrand::HyperV),
        (r"SOFTWARE\Wine",                               VMBrand::Wine),
        (r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD",  VMBrand::VMware),
        (r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE",  VMBrand::VBox),
        (r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_5853",  VMBrand::Xen),
        (r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AF4",  VMBrand::QEMUKVM),
        (r"HARDWARE\ACPI\DSDT\VBOX__",                   VMBrand::VBox),
        (r"HARDWARE\ACPI\FADT\VBOX__",                   VMBrand::VBox),
        (r"HARDWARE\ACPI\RSDT\VBOX__",                   VMBrand::VBox),
        (r"HARDWARE\ACPI\DSDT\BOCHS_",                   VMBrand::Bochs),
        (r"HARDWARE\ACPI\DSDT\BXPC__",                   VMBrand::Bochs),
        (r"SYSTEM\CurrentControlSet\Services\VBoxGuest", VMBrand::VBox),
        (r"SYSTEM\CurrentControlSet\Services\vmci",      VMBrand::VMware),
        (r"SYSTEM\CurrentControlSet\Services\vmhgfs",    VMBrand::VMware),
        (r"SOFTWARE\Oracle\VirtualBox Guest Additions",  VMBrand::VBox),
        (r"SYSTEM\CurrentControlSet\Services\VBoxService", VMBrand::VBox),
        (r"SYSTEM\CurrentControlSet\Services\VBoxSF",    VMBrand::VBox),
    ];

    let hklm = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    for &(path, brand) in KEYS {
        if hklm.open_subkey(path).is_ok() {
            add_brand_score(brand, 0);
            return true;
        }
    }
    false
}

// ── gamarue ───────────────────────────────────────────────────────────────────

/// Check a registry path used by Gamarue malware analysis environments.
pub fn gamarue() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\gamarue.exe")
        .is_ok()
}

// ── vpc_invalid ───────────────────────────────────────────────────────────────

/// Execute the invalid VPC backdoor opcode (0F 3F 07 0B) and check for an
/// exception; on real hardware an exception is raised, VPC handles it silently.
pub fn vpc_invalid() -> bool {
    #[cfg(not(target_arch = "x86_64"))]
    return false;

    // VPC backdoor detection via invalid instruction; on Windows x64 with
    // SEH we can catch it.  In Rust we use a simple signal/vectored-exception
    // handler shortcut: just attempt and assume false if exception occurs.
    // A proper implementation requires a VEH.
    #[cfg(target_arch = "x86_64")]
    {
        // The invalid opcode check is inherently MSVC SEH dependent.
        // Without a VEH, we can't safely run `0F 3F 07 0B` and catch a #UD.
        // Conservative: return false (skip) – will not produce false positives.
        false
    }
}

// ── vmware_str ────────────────────────────────────────────────────────────────

/// Retrieve the hypervisor vendor string via CPUID and check for "VMware".
pub fn vmware_str() -> bool {
    use crate::cpu::{cpuid, is_leaf_supported, vendor_string};

    if !is_leaf_supported(0x4000_0000) {
        return false;
    }
    let r = cpuid(0x4000_0000, 0);
    let v = vendor_string(r.ebx, r.ecx, r.edx);
    if v.contains("VMwareVMware") {
        add_brand_score(VMBrand::VMware, 0);
        true
    } else {
        false
    }
}

// ── cuckoo_dir ────────────────────────────────────────────────────────────────

/// Check for Cuckoo sandbox working directories.
pub fn cuckoo_dir() -> bool {
    static PATHS: &[&str] = &[
        "C:\\cuckoo",
        "C:\\cuckoo\\",
        "C:\\CuckooSandbox",
    ];
    for &p in PATHS {
        if util::exists(p) {
            add_brand_score(VMBrand::Cuckoo, 0);
            return true;
        }
    }
    false
}

// ── cuckoo_pipe ───────────────────────────────────────────────────────────────

/// Check for the Cuckoo sandbox named pipe.
pub fn cuckoo_pipe() -> bool {
    unsafe {
        let found = try_open_device(b"\\\\.\\pipe\\cuckoo\0");
        if found {
            add_brand_score(VMBrand::Cuckoo, 0);
        }
        found
    }
}

// ── display ───────────────────────────────────────────────────────────────────

/// Scan display device strings for known VM graphics adapters.
pub fn display() -> bool {
    use windows_sys::Win32::Graphics::Gdi::{DISPLAY_DEVICEA, EnumDisplayDevicesA};

    unsafe {
        let mut dd = std::mem::zeroed::<DISPLAY_DEVICEA>();
        dd.cb = std::mem::size_of::<DISPLAY_DEVICEA>() as u32;

        static STRINGS: &[(&str, VMBrand)] = &[
            ("VMware",       VMBrand::VMware),
            ("VirtualBox",   VMBrand::VBox),
            ("VBoxDisp",     VMBrand::VBox),
            ("Microsoft Basic Display", VMBrand::HyperV),
            ("QEMU",         VMBrand::QEMU),
            ("Hyper-V",      VMBrand::HyperV),
            ("Parallels",    VMBrand::Parallels),
        ];

        let mut idx = 0u32;
        while EnumDisplayDevicesA(std::ptr::null(), idx, &mut dd, 0) != FALSE {
            let name = std::ffi::CStr::from_ptr(dd.DeviceString.as_ptr() as *const i8)
                .to_string_lossy();
            for &(sig, brand) in STRINGS {
                if name.contains(sig) {
                    add_brand_score(brand, 0);
                    return true;
                }
            }
            idx += 1;
        }
        false
    }
}

// ── device_string ─────────────────────────────────────────────────────────────

/// Scan \\.\<device> paths for known VM device names.
pub fn device_string() -> bool {
    static DEVICES: &[(&[u8], VMBrand)] = &[
        (b"\\\\.\\VBoxMiniRdrDN\0",  VMBrand::VBox),
        (b"\\\\.\\VBoxGuest\0",      VMBrand::VBox),
        (b"\\\\.\\VBoxTrayIPC\0",    VMBrand::VBox),
        (b"\\\\.\\HGFS\0",           VMBrand::VMware),
        (b"\\\\.\\vmci\0",           VMBrand::VMware),
        (b"\\\\.\\vmmemctl\0",       VMBrand::VMware),
        (b"\\\\.\\Global\\vmci\0",   VMBrand::VMware),
    ];

    unsafe {
        for &(dev, brand) in DEVICES {
            if try_open_device(dev) {
                add_brand_score(brand, 0);
                return true;
            }
        }
        false
    }
}

// ── drivers ───────────────────────────────────────────────────────────────────

/// Query loaded kernel drivers and look for VM driver names.
pub fn drivers() -> bool {
    use windows_sys::Win32::System::SystemInformation::{
        NtQuerySystemInformation, SystemModuleInformation,
    };

    static DRIVER_LIST: &[(&str, VMBrand)] = &[
        ("vboxdrv",    VMBrand::VBox),
        ("VBoxGuest",  VMBrand::VBox),
        ("VBoxMouse",  VMBrand::VBox),
        ("VBoxVideo",  VMBrand::VBox),
        ("VBoxSF",     VMBrand::VBox),
        ("vmxnet",     VMBrand::VMware),
        ("vmx_svga",   VMBrand::VMware),
        ("vmx_fb",     VMBrand::VMware),
        ("vmci",       VMBrand::VMware),
        ("VMToolsHook", VMBrand::VMware),
        ("vmmouse",    VMBrand::VMware),
        ("vmhgfs",     VMBrand::VMware),
        ("vmkbd",      VMBrand::VMware),
        ("vmaudio",    VMBrand::VMware),
        ("pvscsi",     VMBrand::VMware),
        ("vmxnet3",    VMBrand::VMware),
        ("kvm",        VMBrand::KVM),
        ("vioscsi",    VMBrand::QEMUKVM),
        ("vioinput",   VMBrand::QEMUKVM),
        ("balloon",    VMBrand::QEMUKVM),
        ("Viostor",    VMBrand::QEMUKVM),
        ("netkvm",     VMBrand::QEMUKVM),
        ("xenvif",     VMBrand::Xen),
        ("xennet",     VMBrand::Xen),
        ("xenstor",    VMBrand::Xen),
        ("xenbus",     VMBrand::Xen),
        ("prl_fs",     VMBrand::Parallels),
        ("prl_eth",    VMBrand::Parallels),
        ("prl_tg",     VMBrand::Parallels),
    ];

    unsafe {
        // Query required buffer size via syscall-spoofed NtQuerySystemInformation.
        let mut size: u32 = 0;
        nt_qsi(11, std::ptr::null_mut(), 0, &mut size);
        if size == 0 {
            size = 256 * 1024;
        }

        let mut buf = vec![0u8; size as usize];
        let status = nt_qsi(11, buf.as_mut_ptr(), size, &mut size);
        if status < 0 {
            return false;
        }

        // buf points to RTL_PROCESS_MODULES:
        //   ULONG NumberOfModules; followed by RTL_PROCESS_MODULE_INFORMATION[NumberOfModules]
        // RTL_PROCESS_MODULE_INFORMATION is 296 bytes on x64.
        const MODULE_INFO_SIZE: usize = 296;
        let count = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        let base = 8; // offset past NumberOfModules + padding on x64

        for i in 0..count {
            let off = base + i * MODULE_INFO_SIZE;
            // FullPathName is at offset 24, length 256
            if off + 24 + 256 > buf.len() {
                break;
            }
            let name_bytes = &buf[off + 24..off + 24 + 256];
            let name = std::str::from_utf8(name_bytes)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_lowercase();

            for &(drv, brand) in DRIVER_LIST {
                if name.contains(&drv.to_lowercase()) {
                    add_brand_score(brand, 0);
                    return true;
                }
            }
        }
        false
    }
}

// ── disk_serial ───────────────────────────────────────────────────────────────

/// Check disk serial/model strings for VM patterns.
pub fn disk_serial() -> bool {
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        StorageDeviceProperty, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR,
        STORAGE_PROPERTY_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::GENERIC_READ;

    unsafe {
        let h = CreateFileA(
            b"\\\\.\\PhysicalDrive0\0".as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        );
        if h == INVALID_HANDLE_VALUE || h == 0 {
            return false;
        }

        let mut query = std::mem::zeroed::<STORAGE_PROPERTY_QUERY>();
        query.PropertyId = StorageDeviceProperty;

        let mut buf = vec![0u8; 1024];
        let mut bytes = 0u32;

        let ok = DeviceIoControl(
            h,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query as *const _ as *const _,
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            &mut bytes,
            std::ptr::null_mut(),
        );
        CloseHandle(h);

        if ok == FALSE {
            return false;
        }

        // STORAGE_DEVICE_DESCRIPTOR has SerialNumberOffset and ProductIdOffset
        let desc = &*(buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR);
        let serial_off = desc.SerialNumberOffset as usize;
        let product_off = desc.ProductIdOffset as usize;

        let get_str = |off: usize| -> String {
            if off == 0 || off >= buf.len() {
                return String::new();
            }
            let end = buf[off..].iter().position(|&b| b == 0).unwrap_or(64);
            String::from_utf8_lossy(&buf[off..off + end]).to_string()
        };

        let serial = get_str(serial_off);
        let product = get_str(product_off);

        static PATTERNS: &[(&str, VMBrand)] = &[
            ("QM000",    VMBrand::VMware),   // VMware serial prefix
            ("VMware",   VMBrand::VMware),
            ("VBOX",     VMBrand::VBox),
            ("VIRTUAL",  VMBrand::HyperV),
            ("QEMU",     VMBrand::QEMU),
        ];

        for &(pat, brand) in PATTERNS {
            let u = pat.to_uppercase();
            if serial.to_uppercase().contains(&u) || product.to_uppercase().contains(&u) {
                add_brand_score(brand, 0);
                return true;
            }
        }

        // VMware also uses "VB" + 8 hex chars format
        if serial.starts_with("VB") && serial.len() >= 10 {
            let hex_part = &serial[2..10];
            if hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                add_brand_score(VMBrand::VBox, 0);
                return true;
            }
        }

        false
    }
}

// ── ivshmem ───────────────────────────────────────────────────────────────────

/// Check if the IVSHMEM device is present via its registry key.
pub fn ivshmem() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // IVSHMEM PCI class GUID
    let path = r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AF4&DEV_1110";
    if let Ok(key) = hklm.open_subkey(path) {
        // Count sub-keys – if > 0 the device is present
        return key.enum_keys().count() > 0;
    }
    false
}

// ── gpu_capabilities ──────────────────────────────────────────────────────────

/// VMs often lack hardware-accelerated color profile management (COLORMGMTCAPS == 0).
pub fn gpu_capabilities() -> bool {
    use windows_sys::Win32::Graphics::Gdi::{GetDC, GetDeviceCaps, ReleaseDC, COLORMGMTCAPS};

    unsafe {
        let hdc = GetDC(0);
        if hdc == 0 {
            return false;
        }
        let caps = GetDeviceCaps(hdc, COLORMGMTCAPS as i32);
        ReleaseDC(0, hdc);
        caps == 0
    }
}

// ── handles ───────────────────────────────────────────────────────────────────

/// Try opening known VM device handles.
pub fn handles() -> bool {
    static DEVICES: &[(&[u8], VMBrand)] = &[
        (b"\\\\.\\VBoxMiniRdrDN\0",  VMBrand::VBox),
        (b"\\\\.\\HGFS\0",           VMBrand::VMware),
        (b"\\\\.\\vmci\0",           VMBrand::VMware),
        (b"\\\\.\\pipe\\cuckoo\0",   VMBrand::Cuckoo),
    ];

    unsafe {
        for &(dev, brand) in DEVICES {
            if try_open_device(dev) {
                add_brand_score(brand, 0);
                return true;
            }
        }
        false
    }
}

// ── virtual_processors ────────────────────────────────────────────────────────

/// Hyper-V reports virtual processor info via registry.
pub fn virtual_processors() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters")
    {
        let _: String = match key.get_value("VirtualMachineName") {
            Ok(v) => { add_brand_score(VMBrand::HyperV, 0); return true; v }
            Err(_) => String::new(),
        };
    }
    if let Ok(key) = hklm.open_subkey(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") {
        if let Ok(name) = key.get_value::<String, _>("ProcessorNameString") {
            if name.contains("Virtual") {
                add_brand_score(VMBrand::HyperV, 0);
                return true;
            }
        }
    }
    false
}

// ── hypervisor_query ──────────────────────────────────────────────────────────

/// NtQuerySystemInformation class 0x9F (SystemHypervisorDetailInformation).
///
/// **Root-partition guard**: NtQuerySystemInformation(0x9F) returns non-zero on
/// Hyper-V root partitions too (the host OS runs virtualised), so we skip on
/// `Enlightenment` to avoid a false positive on the Hyper-V HOST machine.
pub fn hypervisor_query() -> bool {
    use crate::types::HyperXState;
    if crate::util::hyper_x() == HyperXState::Enlightenment {
        return false;
    }
    unsafe {
        let mut buf = [0u8; 256];
        let mut size = 0u32;
        // Spoofed syscall: avoids the ntdll hook Windows Defender ATP places on
        // NtQuerySystemInformation to detect hypervisor-awareness probing.
        let status = nt_qsi(0x9F, buf.as_mut_ptr(), buf.len() as u32, &mut size);
        status == 0 && buf[0] != 0
    }
}

// ── audio ─────────────────────────────────────────────────────────────────────

/// VMs typically have no audio render endpoints in the MMDevices registry.
pub fn audio() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render")
    {
        let subkey_count = key.enum_keys().count();
        let value_count = key.enum_values().count();
        return subkey_count == 0 && value_count == 0;
    }
    // If the key doesn't exist at all that's also unusual
    true
}

// ── acpi_signature ────────────────────────────────────────────────────────────

/// Scan PCI hardware IDs in SetupAPI for known VM vendor IDs.
pub fn acpi_signature() -> bool {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiGetClassDevsA, SetupDiGetDeviceRegistryPropertyA,
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
        DIGCF_ALLCLASSES, DIGCF_PRESENT, SPDRP_HARDWAREID,
        SP_DEVINFO_DATA,
    };
    use windows_sys::Win32::Foundation::GUID;

    static PCI_VM_IDS: &[(&str, VMBrand)] = &[
        ("VEN_15AD", VMBrand::VMware),
        ("VEN_80EE", VMBrand::VBox),
        ("VEN_1AF4", VMBrand::QEMUKVM),
        ("VMBUS",    VMBrand::HyperV),
        ("VPCI",     VMBrand::HyperV),
        ("VEN_5853", VMBrand::Xen),
        ("VEN_1AB8", VMBrand::Parallels),
    ];

    unsafe {
        let hdev = SetupDiGetClassDevsA(
            std::ptr::null(),
            std::ptr::null(),
            0,
            DIGCF_ALLCLASSES | DIGCF_PRESENT,
        );
        if hdev as isize == -1 {
            return false;
        }

        let mut dev_info = std::mem::zeroed::<SP_DEVINFO_DATA>();
        dev_info.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

        let mut found = false;
        let mut idx = 0u32;
        while SetupDiEnumDeviceInfo(hdev, idx, &mut dev_info) != FALSE {
            idx += 1;
            let mut buf = vec![0u8; 1024];
            let mut required = 0u32;
            if SetupDiGetDeviceRegistryPropertyA(
                hdev,
                &dev_info,
                SPDRP_HARDWAREID,
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut required,
            ) != FALSE
            {
                let id = String::from_utf8_lossy(&buf[..required as usize])
                    .to_uppercase();
                for &(vid, brand) in PCI_VM_IDS {
                    if id.contains(vid) {
                        add_brand_score(brand, 0);
                        found = true;
                        break;
                    }
                }
            }
            if found { break; }
        }

        SetupDiDestroyDeviceInfoList(hdev);
        found
    }
}

// ── trap ──────────────────────────────────────────────────────────────────────

/// Trap flag detection – VMs may not emulate single-step traps correctly.
pub fn trap() -> bool {
    // Requires SEH/VEH to catch the debug exception.
    // Conservative: skip on Rust without a VEH.
    false
}

// ── ud ────────────────────────────────────────────────────────────────────────

/// Undefined instruction test (relies on SEH to catch #UD on bare metal).
pub fn ud() -> bool {
    false
}

// ── blockstep ─────────────────────────────────────────────────────────────────

/// Block step (BTF) detection via exception; not implement-able without SEH.
pub fn blockstep() -> bool {
    false
}

// ── dbvm_hypercall ────────────────────────────────────────────────────────────

/// DBVM blue pill detection via a VMCALL / VMMCALL instruction.
pub fn dbvm_hypercall() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // CPUID leaf in range 0x80000000..0x8FFFFFFF checked by DBVM
        let r = crate::cpu::cpuid(0x8000_FFFF, 0);
        // DBVM responds with "DBVM" in EAX
        if r.eax == 0x4D564244 {
            add_brand_score(VMBrand::DBVM, 0);
            return true;
        }
        false
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

// ── boot_logo ─────────────────────────────────────────────────────────────────

/// NtQuerySystemInformation class 140 (SystemBootEnvironmentInformation) to
/// check boot logo vendor strings.
pub fn boot_logo() -> bool {
    unsafe {
        let mut buf = [0u8; 512];
        let mut size = 0u32;
        // Spoofed syscall: bypasses ntdll hooks.
        let status = nt_qsi(140, buf.as_mut_ptr(), buf.len() as u32, &mut size);
        if status != 0 { return false; }

        let text = String::from_utf8_lossy(&buf[..size as usize]).to_uppercase();
        let vm_strings = ["EDK II", "HYPER", "VBOX", "SEABIOS", "QEMU", "OVMF"];
        for s in &vm_strings {
            if text.contains(s) {
                return true;
            }
        }
        false
    }
}

// ── kernel_objects ────────────────────────────────────────────────────────────

/// Enumerate the \\Device object directory for known VM device names.
///
/// On x86-64 every NT call (NtOpenDirectoryObject, NtQueryDirectoryObject,
/// NtClose) is issued via direct `syscall`, bypassing any ntdll inline hooks.
pub fn kernel_objects() -> bool {
    static VM_OBJECTS: &[(&str, VMBrand)] = &[
        ("VmGenerationCounter", VMBrand::HyperV),
        ("VmGid",               VMBrand::HyperV),
        ("VBoxGuest",           VMBrand::VBox),
        ("vmci",                VMBrand::VMware),
    ];

    // Shared scan logic: given a filled buffer, check for VM object names.
    let scan = |buf: &[u8]| -> Option<VMBrand> {
        let words: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16_lossy(&words);
        for &(nm, brand) in VM_OBJECTS {
            if text.contains(nm) {
                return Some(brand);
            }
        }
        None
    };

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let dev_name: Vec<u16> = "\\Device\0".encode_utf16().collect();
        let mut us = crate::syscall::init_unicode_string(&dev_name);
        let mut oa = crate::syscall::ObjectAttributes::new_named(&mut us);

        let mut dir_handle: usize = 0;
        let status =
            crate::syscall::nt_open_directory_object(&mut dir_handle, 0x0001, &mut oa);
        if status != 0 {
            return false;
        }

        let mut buf = vec![0u8; 65536];
        let mut ctx = 0u32;
        let mut restart = 1u8;
        let mut found = false;

        loop {
            let mut ret_len = 0u32;
            let s = crate::syscall::nt_query_directory_object(
                dir_handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                0,
                restart,
                &mut ctx,
                &mut ret_len,
            );
            restart = 0;
            if s != 0 {
                break;
            }
            if let Some(brand) = scan(&buf[..ret_len.min(buf.len() as u32) as usize]) {
                add_brand_score(brand, 0);
                found = true;
                break;
            }
        }

        crate::syscall::nt_close(dir_handle);
        return found;
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        // Fallback: resolve via GetProcAddress when direct syscall is unavailable.
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 {
            return false;
        }

        type RtlInitUs = unsafe extern "system" fn(*mut KoUnicodeString, *const u16);
        type NtOpenDir =
            unsafe extern "system" fn(*mut HANDLE, u32, *mut KoObjectAttributes) -> i32;
        type NtQueryDir =
            unsafe extern "system" fn(HANDLE, *mut u8, u32, u8, u8, *mut u32, *mut u32) -> i32;
        type NtCloseT = unsafe extern "system" fn(HANDLE) -> i32;

        macro_rules! get_p {
            ($name:literal) => {
                std::mem::transmute::<_, _>(GetProcAddress(
                    ntdll,
                    concat!($name, "\0").as_ptr() as *const u8,
                )?)
            };
        }

        let rtl_init: RtlInitUs = get_p!("RtlInitUnicodeString");
        let nt_open: NtOpenDir = get_p!("NtOpenDirectoryObject");
        let nt_query: NtQueryDir = get_p!("NtQueryDirectoryObject");
        let nt_close: NtCloseT = get_p!("NtClose");

        let dev_name: Vec<u16> = "\\Device\0".encode_utf16().collect();
        let mut us = std::mem::zeroed::<KoUnicodeString>();
        rtl_init(&mut us, dev_name.as_ptr());

        let mut oa = std::mem::zeroed::<KoObjectAttributes>();
        oa.length = std::mem::size_of::<KoObjectAttributes>() as u32;
        oa.object_name = &mut us as *mut _;
        oa.attributes = 0x40;

        let mut dir_handle: HANDLE = 0;
        if nt_open(&mut dir_handle, 0x0001, &mut oa) != 0 {
            return false;
        }

        let mut buf = vec![0u8; 65536];
        let mut ctx = 0u32;
        let mut restart = 1u8;
        let mut found = false;

        loop {
            let mut ret_len = 0u32;
            let s = nt_query(
                dir_handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                0,
                restart,
                &mut ctx,
                &mut ret_len,
            );
            restart = 0;
            if s != 0 {
                break;
            }
            if let Some(brand) = scan(&buf[..ret_len.min(buf.len() as u32) as usize]) {
                add_brand_score(brand, 0);
                found = true;
                break;
            }
        }

        nt_close(dir_handle);
        found
    }
}

// NT structures for the non-x86_64 kernel_objects() fallback path.
#[repr(C)]
struct KoUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct KoObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut KoUnicodeString,
    attributes: u32,
    security_descriptor: *mut u8,
    security_quality_of_service: *mut u8,
}

// ── nvram ─────────────────────────────────────────────────────────────────────

/// Check NVRAM/EFI variables for VM indicators.
pub fn nvram() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // EFI System Partition GUID key normally present on real hardware
    if let Ok(key) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State") {
        if let Ok(v) = key.get_value::<u32, _>("UEFISecureBootEnabled") {
            if v == 0 {
                // Secure Boot disabled could indicate VM or legacy BIOS
                // Not definitive alone
            }
        }
    }

    // Check for QEMU-specific EFI variables
    let path = r"HARDWARE\UEFI\ESRT\Entries";
    if let Ok(key) = hklm.open_subkey(path) {
        for subkey_result in key.enum_keys() {
            if let Ok(sk_name) = subkey_result {
                if sk_name.to_uppercase().contains("QEMU") || sk_name.to_uppercase().contains("VBOX") {
                    return true;
                }
            }
        }
    }

    false
}

// ── edid ─────────────────────────────────────────────────────────────────────

/// Check EDID monitor data for VM monitor emulators.
pub fn edid() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = r"SYSTEM\CurrentControlSet\Enum\DISPLAY";
    if let Ok(display_key) = hklm.open_subkey(path) {
        for monitor_result in display_key.enum_keys() {
            let monitor_name = match monitor_result {
                Ok(n) => n,
                Err(_) => continue,
            };
            let monitor_path = format!(r"{}\{}", path, monitor_name);
            if let Ok(mkey) = hklm.open_subkey(&monitor_path) {
                for inst_result in mkey.enum_keys() {
                    let inst = match inst_result {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let edid_path = format!(r"{}\{}\Device Parameters", monitor_path, inst);
                    if let Ok(ekey) = hklm.open_subkey(&edid_path) {
                        let edid_data: Vec<u8> = match ekey.get_raw_value("EDID") {
                            Ok(v) => v.bytes,
                            Err(_) => continue,
                        };
                        // Validate EDID header: [0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00]
                        if edid_data.len() < 8 {
                            continue;
                        }
                        let header = [0x00u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
                        if edid_data[..8] != header {
                            // Invalid/fake EDID header → VM
                            add_brand_score(VMBrand::VMware, 0);
                            return true;
                        }
                        // Check manufacturer ID bytes 8-9
                        // VMware: "VMW" = 0xD69C, VBox: similar
                        if edid_data.len() >= 10 {
                            let mfr = u16::from_be_bytes([edid_data[8], edid_data[9]]);
                            // VMware vendor code
                            if mfr == 0xD69C {
                                add_brand_score(VMBrand::VMware, 0);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

// ── cpu_heuristic ─────────────────────────────────────────────────────────────

/// Heuristic: single-core CPU on modern Windows is uncommon – VM indicator.
pub fn cpu_heuristic() -> bool {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    unsafe {
        let mut si = std::mem::zeroed::<SYSTEM_INFO>();
        GetSystemInfo(&mut si);
        si.dwNumberOfProcessors == 1
    }
}

// ── clock ─────────────────────────────────────────────────────────────────────

/// Check for PNP0100 (PC System Timer) in device list; its absence is common in VMs.
pub fn clock() -> bool {
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiGetClassDevsA, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
        SetupDiGetDeviceRegistryPropertyA, DIGCF_ALLCLASSES, DIGCF_PRESENT,
        SPDRP_HARDWAREID, SP_DEVINFO_DATA,
    };

    unsafe {
        let hdev = SetupDiGetClassDevsA(
            std::ptr::null(),
            std::ptr::null(),
            0,
            DIGCF_ALLCLASSES | DIGCF_PRESENT,
        );
        if hdev as isize == -1 { return false; }

        let mut dev_info = std::mem::zeroed::<SP_DEVINFO_DATA>();
        dev_info.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

        let mut found_timer = false;
        let mut idx = 0u32;
        while SetupDiEnumDeviceInfo(hdev, idx, &mut dev_info) != FALSE {
            idx += 1;
            let mut buf = vec![0u8; 512];
            let mut required = 0u32;
            if SetupDiGetDeviceRegistryPropertyA(
                hdev,
                &dev_info,
                SPDRP_HARDWAREID,
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut required,
            ) != FALSE
            {
                let id = String::from_utf8_lossy(&buf[..required as usize]).to_uppercase();
                if id.contains("PNP0100") {
                    found_timer = true;
                    break;
                }
            }
        }

        SetupDiDestroyDeviceInfoList(hdev);
        // If PC System Timer is missing → VM
        !found_timer
    }
}

// ── msr ───────────────────────────────────────────────────────────────────────

/// Attempt to read a reserved MSR; on real hardware this raises a GP exception.
/// VMs typically handle this silently.
pub fn msr() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // We can't safely use rdmsr without ring-0.
        // As a user-mode approximation: use CPUID to check for VMX/SVM.
        use crate::cpu::cpuid;
        let ecx = cpuid(1, 0).ecx;
        let vmx = (ecx >> 5) & 1 != 0; // VMX bit
        // If VMX is enabled, we might be running under VT-x/VMX
        if vmx {
            return false; // Host could have VT-x enabled; not conclusive
        }
        false
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

// ── kvm_interception ──────────────────────────────────────────────────────────

/// Check for KVM by its CPUID signature.
pub fn kvm_interception() -> bool {
    use crate::cpu::{cpuid, is_leaf_supported, vendor_string};

    if !is_leaf_supported(0x4000_0000) { return false; }
    let r = cpuid(0x4000_0000, 0);
    let v = vendor_string(r.ebx, r.ecx, r.edx);
    if v.contains("KVMKVMKVM") {
        add_brand_score(VMBrand::KVM, 0);
        true
    } else {
        false
    }
}

// ── breakpoint ────────────────────────────────────────────────────────────────

/// Debug register presence check (anti-debug / sandbox detection).
pub fn breakpoint() -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    unsafe { IsDebuggerPresent() != FALSE }
}

// ── azure ─────────────────────────────────────────────────────────────────────

/// Detect Microsoft Azure by checking for the Azure VM metadata registry key.
pub fn azure() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm
        .open_subkey(r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters")
    {
        if let Ok(hostname) = key.get_value::<String, _>("HostName") {
            if hostname.to_lowercase().contains("azure") {
                add_brand_score(VMBrand::AzureHyperV, 0);
                return true;
            }
        }
        // Check "PhysicalHostNameFullyQualified"
        if let Ok(fqdn) = key.get_value::<String, _>("PhysicalHostNameFullyQualified") {
            if fqdn.to_lowercase().contains("azure") {
                add_brand_score(VMBrand::AzureHyperV, 0);
                return true;
            }
        }
    }
    false
}

// ── firmware ─────────────────────────────────────────────────────────────────

/// Scan BIOS/firmware registry strings for VM vendor strings.
pub fn firmware() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    static FIRMWARE_KEYS: &[(&str, &str, VMBrand)] = &[
        (r"HARDWARE\DESCRIPTION\System\BIOS", "BIOSVendor",        VMBrand::Invalid),
        (r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer", VMBrand::Invalid),
        (r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName",  VMBrand::Invalid),
        (r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardManufacturer", VMBrand::Invalid),
    ];

    static VM_STRINGS: &[(&str, VMBrand)] = &[
        ("vmware",      VMBrand::VMware),
        ("virtualbox",  VMBrand::VBox),
        ("innotek",     VMBrand::VBox),
        ("qemu",        VMBrand::QEMU),
        ("bochs",       VMBrand::Bochs),
        ("xen",         VMBrand::Xen),
        ("parallels",   VMBrand::Parallels),
        ("microsoft corporation", VMBrand::HyperV),
        ("seabios",     VMBrand::QEMU),
        ("ovmf",        VMBrand::QEMU),
    ];

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for &(path, value, _) in FIRMWARE_KEYS {
        if let Ok(key) = hklm.open_subkey(path) {
            if let Ok(v) = key.get_value::<String, _>(value) {
                let lower = v.to_lowercase();
                for &(kw, brand) in VM_STRINGS {
                    if lower.contains(kw) {
                        add_brand_score(brand, 0);
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ── devices ───────────────────────────────────────────────────────────────────

/// Scan PCI device hardware IDs for known VM vendor IDs.
pub fn devices() -> bool {
    // Reuse the acpi_signature logic (same SetupAPI scan)
    acpi_signature()
}

// ── system_registers ─────────────────────────────────────────────────────────

/// Check hypervisor-related register bits (x86 only).
///
/// **Root-partition guard**: CPUID leaf 1 ECX bit 31 is set on Hyper-V root
/// partitions; skip to avoid a false positive on the host machine.
pub fn system_registers() -> bool {
    use crate::types::HyperXState;
    if crate::util::hyper_x() == HyperXState::Enlightenment {
        return false;
    }
    use crate::cpu::cpuid;
    let ecx = cpuid(1, 0).ecx;
    (ecx >> 31) & 1 != 0
}
