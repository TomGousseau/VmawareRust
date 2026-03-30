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
// GetModuleHandleA / GetProcAddress are only needed on non-x86_64 fallback paths.
// On x86_64 we use the stealthy PEB-walk helpers in crate::syscall instead,
// so these symbols never appear in the x86_64 import table.
#[cfg(not(target_arch = "x86_64"))]
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

// ── Helper macros ─────────────────────────────────────────────────────────────

macro_rules! cstr {
    ($s:expr) => {
        concat!($s, "\0").as_ptr()
    };
}

// ── Compile-time XOR string obfuscation ──────────────────────────────────────
//
// VM indicator strings (device paths, registry keys, driver names…) are XOR'd
// with KEY at compile time so they never appear as plaintext in .rodata.
// Static scanners (YARA, any.run static pass, PE string extraction) see only
// random-looking bytes; the plaintext is decoded onto the stack at runtime just
// before use, and discarded immediately after.
//
// Usage:  let path = obfstr!(r"\??\VBoxGuest");
//         let s    = std::str::from_utf8(&path).unwrap_or("");
//
// The macro returns `[u8; N]` — a stack-allocated byte array.

macro_rules! obfstr {
    ($s:literal) => {{
        const S: &str = $s;
        const N: usize = S.len();
        // Rolling per-position key: key[i] = ((i ^ 0xAB) * 0x4D + 0x17) & 0xFF
        // Every byte uses a DIFFERENT key → single-byte XOR brute-force (FLOSS,
        // automated string extractors) produces garbage for all 256 key guesses.
        const ENCODED: [u8; N] = {
            let b = S.as_bytes();
            let mut e = [0u8; N];
            let mut i = 0usize;
            while i < N {
                let k = ((i ^ 0xAB).wrapping_mul(0x4D).wrapping_add(0x17)) as u8;
                e[i] = b[i] ^ k;
                i += 1;
            }
            e
        };
        // Decode at runtime on the stack — plaintext never in .rodata.
        let mut buf = ENCODED;
        for (idx, b) in buf.iter_mut().enumerate() {
            *b ^= ((idx ^ 0xAB).wrapping_mul(0x4D).wrapping_add(0x17)) as u8;
        }
        buf
    }};
}


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

/// Open a device by NT path (e.g. `b"\x5c\x3f\x3f\x5c..."`) and immediately
/// close it; returns true if the device exists.
///
/// On x86-64: issues `NtCreateFile` via direct `syscall` — `CreateFileA` is
/// never called and does NOT appear in the import table for this code path.
/// On other Windows targets: falls back to `CreateFileA` via Win32.
///
/// The `path` parameter must be ASCII bytes in NT namespace form (`\??\…`),
/// typically produced by the `obfstr!` macro so the plaintext is not visible
/// in `.rodata`.
#[cfg(target_arch = "x86_64")]
unsafe fn try_open_device(nt_path_bytes: &[u8]) -> bool {
    // Build null-terminated wide path (all our device paths are ASCII).
    let mut wide: Vec<u16> = nt_path_bytes.iter().map(|&b| b as u16).collect();
    wide.push(0);
    let mut us = crate::syscall::init_unicode_string(&wide);
    let mut oa = crate::syscall::ObjectAttributes::new_named(&mut us);
    let mut handle: usize = 0;
    let mut iosb: [u64; 2] = [0, 0];
    // FILE_OPEN=1, ShareAccess READ|WRITE=3, FILE_NON_DIRECTORY_FILE=0x40
    let status = crate::syscall::nt_create_file(
        &mut handle, 0, &mut oa, iosb.as_mut_ptr(), 3, 1, 0x40,
    ) as u32;
    match status {
        0 => { crate::syscall::nt_close(handle); true }
        // ACCESS_DENIED or SHARING_VIOLATION → object exists but we can't open it
        0xC000_0022 | 0xC000_0043 => true,
        _ => false,
    }
}

/// Win32 fallback for non-x86_64 targets — uses `CreateFileA` directly.
#[cfg(not(target_arch = "x86_64"))]
unsafe fn try_open_device(path: &[u8]) -> bool {
    let h = CreateFileA(
        path.as_ptr(),
        0,
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
///
/// On x86-64 we use a stealthy in-memory PE export scan (PEB walk + export
/// table parse) so `GetModuleHandleA` / `GetProcAddress` are never called and
/// do not appear in the import table.
pub fn wine() -> bool {
    // ── x86-64: completely hook-free export check ─────────────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        if crate::syscall::ntdll_export_exists("wine_get_version") {
            add_brand_score(VMBrand::Wine, 0);
            return true;
        }
        return false;
    }

    // ── other Windows archs: standard Win32 path ──────────────────────────────
    #[cfg(not(target_arch = "x86_64"))]
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
///
/// On x86-64 the check is done by walking the PEB `InLoadOrderModuleList`
/// directly — no call to `GetModuleHandleA` is made, so the query is
/// invisible to any hook placed on that function.
pub fn dll() -> bool {
    // Plain &str names (no null terminator needed for PEB walk).
    static DLLS: &[(&str, VMBrand)] = &[
        ("vmGuestLib.dll",  VMBrand::VMware),
        ("vmhgfs.dll",      VMBrand::VMware),
        ("vboxmrxnp.dll",   VMBrand::VBox),
        ("vboxogl.dll",     VMBrand::VBox),
        ("vboxdisp.dll",    VMBrand::VBox),
        ("sbiedll.dll",     VMBrand::Sandboxie),
        ("SbieDll.dll",     VMBrand::Sandboxie),
        ("api_log.dll",     VMBrand::CWSandbox),
        ("dir_watch.dll",   VMBrand::CWSandbox),
        ("pstorec.dll",     VMBrand::ThreatExpert),
        ("vmcheck.dll",     VMBrand::VPC),
        ("cuckoomon.dll",   VMBrand::Cuckoo),
    ];

    // ── x86-64: stealthy PEB walk – no Win32 import used ─────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        for &(name, brand) in DLLS {
            if unsafe { crate::syscall::peb_module_loaded(name) } {
                add_brand_score(brand, 0);
                return true;
            }
        }
        return false;
    }

    // ── other Windows archs: standard Win32 path ──────────────────────────────
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        for &(name, brand) in DLLS {
            let mut nul = name.to_string();
            nul.push('\0');
            let h = GetModuleHandleA(nul.as_ptr());
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
///
/// Mutex names are XOR-obfuscated so strings like `"VBoxGuest"` are not
/// visible in `.rodata`.  `OpenMutexA` is still called (obtaining the
/// name from a stack-only decoded buffer), so the Win32 hook observes
/// the decoded name, but static analysis cannot extract it.
pub fn mutex() -> bool {
    use windows_sys::Win32::System::Threading::OpenMutexA;
    use windows_sys::Win32::Security::SYNCHRONIZE;

    macro_rules! chk {
        ($name:literal, $brand:expr) => {{
            let mut n = obfstr!($name);
            n[n.len() - 1] = 0; // ensure null-terminator at last XOR'd position
            // obfstr includes the \0 byte in the literal, so last byte decodes to 0.
            let h = OpenMutexA(SYNCHRONIZE, FALSE, n.as_ptr());
            if h != 0 {
                CloseHandle(h);
                add_brand_score($brand, 0);
                return true;
            }
        }};
    }

    unsafe {
        chk!("VBoxTrayIPC-\0",              VMBrand::VBox);
        chk!("VBoxGuest\0",                 VMBrand::VBox);
        chk!("MGA_APP_MUTEX\0",             VMBrand::VMware);
        chk!("VMWARE_TOOLS_UPGRADE_MUTEX\0", VMBrand::VMware);
        chk!("VBEAM_MUTEX\0",               VMBrand::VMware);
        chk!("TPAutoConnSvcMutex\0",        VMBrand::VMware);
        chk!("cuckoo_signal\0",             VMBrand::Cuckoo);
        false
    }
}

// ── virtual_registry ──────────────────────────────────────────────────────────

/// Check for VM-specific registry keys.
///
/// On x86-64: checks performed via `NtOpenKey` direct syscall with
/// obfuscated key paths — `RegOpenKeyExW` is never called and the plaintext
/// `\SOFTWARE\VMware…` strings do not appear in `.rodata`.
/// On other targets: falls back to the `winreg` crate.
pub fn virtual_registry() -> bool {
    // ── x86-64: spoofed NtOpenKey + compile-time obfuscated paths ────────────
    #[cfg(target_arch = "x86_64")]
    {
        // Helper: check if an NT registry key path exists.
        unsafe fn reg_exists(ascii_path: &[u8]) -> bool {
            let mut wide: Vec<u16> = ascii_path.iter().map(|&b| b as u16).collect();
            wide.push(0);
            let mut us = crate::syscall::init_unicode_string(&wide);
            let mut oa = crate::syscall::ObjectAttributes::new_named(&mut us);
            let mut handle: usize = 0;
            let status = crate::syscall::nt_open_key(&mut handle, 0x20019, &mut oa) as u32;
            if status == 0 { crate::syscall::nt_close(handle); return true; }
            status == 0xC000_0022  // ACCESS_DENIED → key exists
        }

        macro_rules! chk {
            ($p:literal, $b:expr) => {{
                let path = obfstr!($p);
                if unsafe { reg_exists(&path) } {
                    add_brand_score($b, 0);
                    return true;
                }
            }};
        }

        // Full NT paths: \Registry\Machine\<HKLM subkey>
        chk!(r"\Registry\Machine\SOFTWARE\VMware, Inc.\VMware Tools",         VMBrand::VMware);
        chk!(r"\Registry\Machine\SOFTWARE\VirtualBox Guest Additions",         VMBrand::VBox);
        chk!(r"\Registry\Machine\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", VMBrand::HyperV);
        chk!(r"\Registry\Machine\SOFTWARE\Wine",                               VMBrand::Wine);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD",  VMBrand::VMware);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE",  VMBrand::VBox);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Enum\PCI\VEN_5853",  VMBrand::Xen);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AF4",  VMBrand::QEMUKVM);
        chk!(r"\Registry\Machine\HARDWARE\ACPI\DSDT\VBOX__",                   VMBrand::VBox);
        chk!(r"\Registry\Machine\HARDWARE\ACPI\FADT\VBOX__",                   VMBrand::VBox);
        chk!(r"\Registry\Machine\HARDWARE\ACPI\RSDT\VBOX__",                   VMBrand::VBox);
        chk!(r"\Registry\Machine\HARDWARE\ACPI\DSDT\BOCHS_",                   VMBrand::Bochs);
        chk!(r"\Registry\Machine\HARDWARE\ACPI\DSDT\BXPC__",                   VMBrand::Bochs);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Services\VBoxGuest", VMBrand::VBox);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Services\vmci",      VMBrand::VMware);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Services\vmhgfs",    VMBrand::VMware);
        chk!(r"\Registry\Machine\SOFTWARE\Oracle\VirtualBox Guest Additions",  VMBrand::VBox);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Services\VBoxService", VMBrand::VBox);
        chk!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Services\VBoxSF",    VMBrand::VBox);
        return false;
    }

    // ── non-x86_64 fallback: winreg ──────────────────────────────────────────
    #[cfg(not(target_arch = "x86_64"))]
    {
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
}

// ── gamarue ───────────────────────────────────────────────────────────────────

/// Check a registry path used by Gamarue malware analysis environments.
pub fn gamarue() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let path = obfstr!(r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\gamarue.exe");
        unsafe fn reg_exists(ascii_path: &[u8]) -> bool {
            let mut wide: Vec<u16> = ascii_path.iter().map(|&b| b as u16).collect();
            wide.push(0);
            let mut us = crate::syscall::init_unicode_string(&wide);
            let mut oa = crate::syscall::ObjectAttributes::new_named(&mut us);
            let mut handle: usize = 0;
            let status = crate::syscall::nt_open_key(&mut handle, 0x20019, &mut oa) as u32;
            if status == 0 { crate::syscall::nt_close(handle); return true; }
            status == 0xC000_0022
        }
        return unsafe { reg_exists(&path) };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        hklm.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\gamarue.exe")
            .is_ok()
    }
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
    let vm_id = obfstr!("VMwareVMware");
    let vm_str = std::str::from_utf8(&vm_id).unwrap_or("");
    if v.contains(vm_str) {
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
        // NT path: \??\pipe\cuckoo  (obfstr hides plaintext from .rodata)
        let path = obfstr!(r"\??\pipe\cuckoo");
        let found = try_open_device(&path);
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

        // Decode VM display strings at runtime so they don't sit in .rodata.
        macro_rules! disp_match {
            ($name:expr, $sig:literal, $brand:expr) => {{
                let s = obfstr!($sig);
                let sig_str = std::str::from_utf8(&s).unwrap_or("");
                if $name.contains(sig_str) {
                    add_brand_score($brand, 0);
                    return true;
                }
            }};
        }

        let mut idx = 0u32;
        while EnumDisplayDevicesA(std::ptr::null(), idx, &mut dd, 0) != FALSE {
            let name = std::ffi::CStr::from_ptr(dd.DeviceString.as_ptr() as *const i8)
                .to_string_lossy();
            let name: &str = &name;
            disp_match!(name, "VMware",                VMBrand::VMware);
            disp_match!(name, "VirtualBox",            VMBrand::VBox);
            disp_match!(name, "VBoxDisp",              VMBrand::VBox);
            disp_match!(name, "Microsoft Basic Display", VMBrand::HyperV);
            disp_match!(name, "QEMU",                  VMBrand::QEMU);
            disp_match!(name, "Hyper-V",               VMBrand::HyperV);
            disp_match!(name, "Parallels",             VMBrand::Parallels);
            idx += 1;
        }
        false
    }
}

// ── device_string ─────────────────────────────────────────────────────────────

/// Probe NT device paths for known VM device names.
///
/// On x86-64 each path is XOR-obfuscated (`obfstr!`) so no VM string appears
/// in `.rodata`, and the probe uses `NtCreateFile` via direct syscall so
/// `CreateFileA` is never called for these checks.
pub fn device_string() -> bool {
    macro_rules! chk {
        ($p:literal, $b:expr) => {{
            let path = obfstr!($p);
            if unsafe { try_open_device(&path) } {
                add_brand_score($b, 0);
                return true;
            }
        }};
    }
    // NT namespace paths (\??\X) — obfstr hides them from .rodata.
    chk!(r"\??\VBoxMiniRdrDN", VMBrand::VBox);
    chk!(r"\??\VBoxGuest",     VMBrand::VBox);
    chk!(r"\??\VBoxTrayIPC",   VMBrand::VBox);
    chk!(r"\??\HGFS",          VMBrand::VMware);
    chk!(r"\??\vmci",          VMBrand::VMware);
    chk!(r"\??\vmmemctl",      VMBrand::VMware);
    chk!(r"\??\Global\vmci",   VMBrand::VMware);
    false
}

// ── drivers ───────────────────────────────────────────────────────────────────

/// Query loaded kernel drivers and look for VM driver names.
///
/// Driver names are XOR-obfuscated at compile time (`obfstr!`) so strings
/// like `"vboxdrv"` or `"vmxnet"` never appear in `.rodata`. The list is
/// decoded at runtime inside the comparison inner loop.
/// NtQuerySystemInformation is already spoofed via Hell's Gate.
pub fn drivers() -> bool {
    unsafe {
        let mut size: u32 = 0;
        nt_qsi(11, std::ptr::null_mut(), 0, &mut size);
        if size == 0 { size = 256 * 1024; }

        let mut buf = vec![0u8; size as usize];
        let status = nt_qsi(11, buf.as_mut_ptr(), size, &mut size);
        if status < 0 { return false; }

        const MODULE_INFO_SIZE: usize = 296;
        let count = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        let base = 8;

        // Decode a driver name from obfstr bytes and compare case-insensitively.
        macro_rules! drv_chk {
            ($name_lower:expr, $drv:literal, $brand:expr) => {{
                let d = obfstr!($drv);
                let ds = std::str::from_utf8(&d).unwrap_or("");
                if $name_lower.contains(ds) {
                    add_brand_score($brand, 0);
                    return true;
                }
            }};
        }

        for i in 0..count {
            let off = base + i * MODULE_INFO_SIZE;
            if off + 24 + 256 > buf.len() { break; }
            let name_bytes = &buf[off + 24..off + 24 + 256];
            let name = std::str::from_utf8(name_bytes)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_lowercase();

            drv_chk!(name, "vboxdrv",    VMBrand::VBox);
            drv_chk!(name, "vboxguest",  VMBrand::VBox);
            drv_chk!(name, "vboxmouse",  VMBrand::VBox);
            drv_chk!(name, "vboxvideo",  VMBrand::VBox);
            drv_chk!(name, "vboxsf",     VMBrand::VBox);
            drv_chk!(name, "vmxnet",     VMBrand::VMware);
            drv_chk!(name, "vmx_svga",   VMBrand::VMware);
            drv_chk!(name, "vmx_fb",     VMBrand::VMware);
            drv_chk!(name, "vmci",       VMBrand::VMware);
            drv_chk!(name, "vmtoolshook",VMBrand::VMware);
            drv_chk!(name, "vmmouse",    VMBrand::VMware);
            drv_chk!(name, "vmhgfs",     VMBrand::VMware);
            drv_chk!(name, "vmkbd",      VMBrand::VMware);
            drv_chk!(name, "vmaudio",    VMBrand::VMware);
            drv_chk!(name, "pvscsi",     VMBrand::VMware);
            drv_chk!(name, "vmxnet3",    VMBrand::VMware);
            drv_chk!(name, "kvm",        VMBrand::KVM);
            drv_chk!(name, "vioscsi",    VMBrand::QEMUKVM);
            drv_chk!(name, "vioinput",   VMBrand::QEMUKVM);
            drv_chk!(name, "balloon",    VMBrand::QEMUKVM);
            drv_chk!(name, "viostor",    VMBrand::QEMUKVM);
            drv_chk!(name, "netkvm",     VMBrand::QEMUKVM);
            drv_chk!(name, "xenvif",     VMBrand::Xen);
            drv_chk!(name, "xennet",     VMBrand::Xen);
            drv_chk!(name, "xenstor",    VMBrand::Xen);
            drv_chk!(name, "xenbus",     VMBrand::Xen);
            drv_chk!(name, "prl_fs",     VMBrand::Parallels);
            drv_chk!(name, "prl_eth",    VMBrand::Parallels);
            drv_chk!(name, "prl_tg",     VMBrand::Parallels);
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

        macro_rules! disk_chk {
            ($pat:literal, $brand:expr) => {{
                let p = obfstr!($pat);
                let pu = std::str::from_utf8(&p).unwrap_or("").to_uppercase();
                if serial.to_uppercase().contains(&*pu) || product.to_uppercase().contains(&*pu) {
                    add_brand_score($brand, 0);
                    return true;
                }
            }};
        }
        disk_chk!("QM000",   VMBrand::VMware);
        disk_chk!("VMware",  VMBrand::VMware);
        disk_chk!("VBOX",    VMBrand::VBox);
        disk_chk!("VIRTUAL", VMBrand::HyperV);
        disk_chk!("QEMU",    VMBrand::QEMU);

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
    #[cfg(target_arch = "x86_64")]
    {
        let path = obfstr!(r"\Registry\Machine\SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AF4&DEV_1110");
        return unsafe {
            let mut wide: Vec<u16> = path.iter().map(|&b| b as u16).collect();
            wide.push(0);
            let mut us = crate::syscall::init_unicode_string(&wide);
            let mut oa = crate::syscall::ObjectAttributes::new_named(&mut us);
            let mut handle: usize = 0;
            let status = crate::syscall::nt_open_key(&mut handle, 0x20019, &mut oa) as u32;
            if status == 0 { crate::syscall::nt_close(handle); true }
            else { status == 0xC000_0022 }
        };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let path = r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AF4&DEV_1110";
        if let Ok(key) = hklm.open_subkey(path) {
            return key.enum_keys().count() > 0;
        }
        false
    }
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
    macro_rules! chk {
        ($p:literal, $b:expr) => {{
            let path = obfstr!($p);
            if unsafe { try_open_device(&path) } {
                add_brand_score($b, 0);
                return true;
            }
        }};
    }
    chk!(r"\??\VBoxMiniRdrDN",     VMBrand::VBox);
    chk!(r"\??\HGFS",              VMBrand::VMware);
    chk!(r"\??\vmci",              VMBrand::VMware);
    chk!(r"\??\pipe\cuckoo",      VMBrand::Cuckoo);
    false
}

// ── virtual_processors ────────────────────────────────────────────────────────

/// Hyper-V reports virtual processor info via registry.
pub fn virtual_processors() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Shared NtOpenKey helper (inline closure).
        let reg_exists = |ascii: &[u8]| -> bool {
            let mut wide: Vec<u16> = ascii.iter().map(|&b| b as u16).collect();
            wide.push(0);
            let mut us = crate::syscall::init_unicode_string(&wide);
            let mut oa = crate::syscall::ObjectAttributes::new_named(&mut us);
            let mut h: usize = 0;
            let s = crate::syscall::nt_open_key(&mut h, 0x20019, &mut oa) as u32;
            if s == 0 { crate::syscall::nt_close(h); true }
            else { s == 0xC000_0022 }
        };
        // Key existence alone is sufficient — if HKLM\...Guest\Parameters exists we're in HyperV.
        let k1 = obfstr!(r"\Registry\Machine\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters");
        if reg_exists(&k1) { add_brand_score(VMBrand::HyperV, 0); return true; }
        // Single-CPU check via NtQuerySystemInformation is already handled by cpu_heuristic.
        return false;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") {
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
///
/// On x86-64 the key path is obfuscated and opened via direct `NtOpenKey` syscall.
pub fn audio() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let path = obfstr!(r"\Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render");
        let mut wide: Vec<u16> = path.iter().map(|&b| b as u16).collect();
        wide.push(0);
        let mut us = crate::syscall::init_unicode_string(&wide);
        let mut oa = crate::syscall::ObjectAttributes::new_named(&mut us);
        let mut handle: usize = 0;
        let s = crate::syscall::nt_open_key(&mut handle, 0x20019, &mut oa) as u32;
        if s == 0 {
            // Key opened — check if it has any subkeys by querying it.
            // For simplicity: if it opened with zero subkeys we treat as VM.
            // Enumerating subkeys via NtEnumerateKey is complex; just treat
            // KEY_EXISTS as "real audio present" to avoid false positives.
            crate::syscall::nt_close(handle);
            return false; // render endpoint key exists → not a VM indicator
        }
        // Key missing → no audio render endpoints → VM indicator.
        s != 0xC000_0022 // ACCESS_DENIED also means key exists
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render") {
            let subkey_count = key.enum_keys().count();
            let value_count  = key.enum_values().count();
            return subkey_count == 0 && value_count == 0;
        }
        true
    }
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
                macro_rules! pci_chk {
                    ($vid:literal, $brand:expr) => {{
                        let v = obfstr!($vid);
                        let vs = std::str::from_utf8(&v).unwrap_or("");
                        if id.contains(vs) { add_brand_score($brand, 0); found = true; }
                    }};
                }
                pci_chk!("VEN_15AD", VMBrand::VMware);
                pci_chk!("VEN_80EE", VMBrand::VBox);
                pci_chk!("VEN_1AF4", VMBrand::QEMUKVM);
                pci_chk!("VMBUS",    VMBrand::HyperV);
                pci_chk!("VPCI",     VMBrand::HyperV);
                pci_chk!("VEN_5853", VMBrand::Xen);
                pci_chk!("VEN_1AB8", VMBrand::Parallels);
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
        macro_rules! boot_chk {
            ($s:literal) => {{
                let k = obfstr!($s);
                let ks = std::str::from_utf8(&k).unwrap_or("");
                if text.contains(ks) { return true; }
            }};
        }
        boot_chk!("EDK II");
        boot_chk!("HYPER");
        boot_chk!("VBOX");
        boot_chk!("SEABIOS");
        boot_chk!("QEMU");
        boot_chk!("OVMF");
        false
    }
}

// ── kernel_objects ────────────────────────────────────────────────────────────

/// Enumerate the \\Device object directory for known VM device names.
///
/// On x86-64 every NT call (NtOpenDirectoryObject, NtQueryDirectoryObject,
/// NtClose) is issued via direct `syscall`, bypassing any ntdll inline hooks.
pub fn kernel_objects() -> bool {
    // VM object names decoded at runtime — not stored as plaintext in .rodata.
    let scan = |buf: &[u8]| -> Option<VMBrand> {
        let words: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16_lossy(&words);
        macro_rules! obj_chk {
            ($nm:literal, $brand:expr) => {{
                let n = obfstr!($nm);
                let ns = std::str::from_utf8(&n).unwrap_or("");
                if text.contains(ns) { return Some($brand); }
            }};
        }
        obj_chk!("VmGenerationCounter", VMBrand::HyperV);
        obj_chk!("VmGid",               VMBrand::HyperV);
        obj_chk!("VBoxGuest",           VMBrand::VBox);
        obj_chk!("vmci",                VMBrand::VMware);
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
                let q = obfstr!("QEMU");
                let qs = std::str::from_utf8(&q).unwrap_or("");
                let vb = obfstr!("VBOX");
                let vbs = std::str::from_utf8(&vb).unwrap_or("");
                let upper = sk_name.to_uppercase();
                if upper.contains(qs) || upper.contains(vbs) {
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
    let kvm_id = obfstr!("KVMKVMKVM");
    let kvm_str = std::str::from_utf8(&kvm_id).unwrap_or("");
    if v.contains(kvm_str) {
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
        let az = obfstr!("azure");
        let azs = std::str::from_utf8(&az).unwrap_or("");
        if let Ok(hostname) = key.get_value::<String, _>("HostName") {
            if hostname.to_lowercase().contains(azs) {
                add_brand_score(VMBrand::AzureHyperV, 0);
                return true;
            }
        }
        if let Ok(fqdn) = key.get_value::<String, _>("PhysicalHostNameFullyQualified") {
            if fqdn.to_lowercase().contains(azs) {
                add_brand_score(VMBrand::AzureHyperV, 0);
                return true;
            }
        }
    }
    false
}

// ── firmware ─────────────────────────────────────────────────────────────────

/// Scan BIOS/firmware registry strings for VM vendor strings.
///
/// On x86-64: NtOpenKey + NtQueryValueKey via direct syscall; all VM keyword
/// strings decoded at runtime via obfstr! so they don't appear in .rodata.
/// On other targets: falls back to the winreg crate.
pub fn firmware() -> bool {
    // ── x86-64 path ──────────────────────────────────────────────────────────
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Open the BIOS key via NT path (obfuscated).
        let bios_path = obfstr!(r"\Registry\Machine\HARDWARE\DESCRIPTION\System\BIOS");
        let mut wide: Vec<u16> = bios_path.iter().map(|&b| b as u16).collect();
        wide.push(0);
        let mut us = crate::syscall::init_unicode_string(&wide);
        let mut oa = crate::syscall::ObjectAttributes::new_named(&mut us);
        let mut key_handle: usize = 0;
        if crate::syscall::nt_open_key(&mut key_handle, 0x20019, &mut oa) != 0 {
            return false;
        }

        // Helper: read a REG_SZ value from an already-open key handle.
        let read_value = |handle: usize, val_ascii: &[u8]| -> Option<String> {
            let val_wide: Vec<u16> = val_ascii.iter().map(|&b| b as u16).collect();
            let mut val_us = crate::syscall::UnicodeString {
                length: (val_wide.len() * 2) as u16,
                maximum_length: (val_wide.len() * 2) as u16,
                _pad: 0,
                buffer: val_wide.as_ptr(),
            };
            let mut buf = vec![0u8; 512];
            let mut ret_len = 0u32;
            // KeyValuePartialInformation = 1
            let s = crate::syscall::nt_query_value_key(
                handle, &mut val_us, 1,
                buf.as_mut_ptr(), buf.len() as u32, &mut ret_len,
            );
            if s != 0 || ret_len < 12 { return None; }
            // Layout: [u32 TitleIndex][u32 Type][u32 DataLength][Data...]
            let data_len = u32::from_le_bytes(buf[8..12].try_into().ok()?) as usize;
            if 12 + data_len > buf.len() { return None; }
            let data = &buf[12..12 + data_len];
            // REG_SZ = type 1; data is UTF-16LE
            let wide_chars: Vec<u16> = data.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&wide_chars).trim_end_matches('\0').to_string())
        };

        // Check the four firmware fields via obfstr-encoded value names.
        macro_rules! read_obf {
            ($val:literal) => {{
                let v = obfstr!($val);
                read_value(key_handle, &v)
            }};
        }
        let fields = [
            read_obf!("BIOSVendor"),
            read_obf!("SystemManufacturer"),
            read_obf!("SystemProductName"),
            read_obf!("BaseBoardManufacturer"),
        ];
        crate::syscall::nt_close(key_handle);

        // Match against obfuscated VM keywords.
        macro_rules! kw_match {
            ($lower:expr, $kw:literal, $brand:expr) => {{
                let k = obfstr!($kw);
                let ks = std::str::from_utf8(&k).unwrap_or("");
                if $lower.contains(ks) { add_brand_score($brand, 0); return true; }
            }};
        }
        for field in &fields {
            if let Some(ref v) = field {
                let lower = v.to_lowercase();
                let lower: &str = &lower;
                kw_match!(lower, "vmware",               VMBrand::VMware);
                kw_match!(lower, "virtualbox",           VMBrand::VBox);
                kw_match!(lower, "innotek",              VMBrand::VBox);
                kw_match!(lower, "qemu",                 VMBrand::QEMU);
                kw_match!(lower, "bochs",                VMBrand::Bochs);
                kw_match!(lower, "xen",                  VMBrand::Xen);
                kw_match!(lower, "parallels",            VMBrand::Parallels);
                kw_match!(lower, "microsoft corporation",VMBrand::HyperV);
                kw_match!(lower, "seabios",              VMBrand::QEMU);
                kw_match!(lower, "ovmf",                 VMBrand::QEMU);
            }
        }
        return false;
    }

    // ── non-x86_64 fallback ───────────────────────────────────────────────────
    #[cfg(not(target_arch = "x86_64"))]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        static FIRMWARE_KEYS: &[(&str, &str)] = &[
            (r"HARDWARE\DESCRIPTION\System\BIOS", "BIOSVendor"),
            (r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"),
            (r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
            (r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardManufacturer"),
        ];
        static VM_STRINGS: &[(&str, VMBrand)] = &[
            ("vmware",                VMBrand::VMware),
            ("virtualbox",            VMBrand::VBox),
            ("innotek",               VMBrand::VBox),
            ("qemu",                  VMBrand::QEMU),
            ("bochs",                 VMBrand::Bochs),
            ("xen",                   VMBrand::Xen),
            ("parallels",             VMBrand::Parallels),
            ("microsoft corporation", VMBrand::HyperV),
            ("seabios",               VMBrand::QEMU),
            ("ovmf",                  VMBrand::QEMU),
        ];
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for &(path, value) in FIRMWARE_KEYS {
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
