//! Hell's Gate + Halo's Gate – direct syscall invocation for Windows x86-64.
//!
//! Bypasses userland API hooks placed by AV/EDR products (e.g. Windows Defender
//! ATP) by reading syscall numbers straight from ntdll.dll's export stubs and
//! invoking the `syscall` instruction directly, never passing through the ntdll
//! trampoline that security software hooks.
//!
//! # Technique overview
//!
//! 1. **PEB walk** – locate ntdll.dll base address through the Process Environment
//!    Block (`gs:[0x60]`), avoiding `GetModuleHandle` which can itself be monitored.
//! 2. **Export table parse** – walk ntdll's PE export directory to find each NT
//!    function's virtual address.
//! 3. **Hell's Gate** – read the syscall number from the unhooked stub bytes
//!    (`4C 8B D1 B8 XX XX XX XX` = `mov r10,rcx ; mov eax,<nr>`).
//! 4. **Halo's Gate** – if a stub is patched (starts with `E9` jmp), scan
//!    neighbouring stubs (which share sequential syscall numbers) to reconstruct
//!    the correct number.
//! 5. **Inline `syscall`** – execute the `syscall` instruction from our own code
//!    page, completely bypassing any inline hooks in ntdll.

#![cfg(all(windows, target_arch = "x86_64"))]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ── Syscall-number cache ──────────────────────────────────────────────────────

static SYSCALL_CACHE: OnceLock<Mutex<HashMap<&'static str, u16>>> = OnceLock::new();

fn nr_cache() -> &'static Mutex<HashMap<&'static str, u16>> {
    SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── PEB walk → ntdll base ─────────────────────────────────────────────────────

/// Return the base address of ntdll.dll by walking the PEB InLoadOrderModuleList.
///
/// This avoids `GetModuleHandleA`, which is exported from kernel32 and is a
/// common hooking target.  The PEB is always accessible at `gs:[0x60]` on
/// Windows x86-64, regardless of any userland hooks.
///
/// # Safety
/// Must only be called on Windows x86-64 with a valid TEB/PEB.
pub unsafe fn ntdll_base() -> Option<*const u8> {
    // Read PEB pointer from TEB (Thread Environment Block) at gs:[0x60].
    let peb: *const u8;
    core::arch::asm!(
        "mov {}, qword ptr gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );
    if peb.is_null() {
        return None;
    }

    // PEB layout (x64):
    //   +0x000  InheritedAddressSpace   (BOOLEAN)
    //   ...
    //   +0x018  Ldr                     (PPEB_LDR_DATA)
    let ldr: *const u8 = *(peb.add(0x18) as *const *const u8);
    if ldr.is_null() {
        return None;
    }

    // PEB_LDR_DATA.InLoadOrderModuleList.Flink is at offset +0x10.
    // Each list entry is the *beginning* of an LDR_DATA_TABLE_ENTRY.
    let list_head = ldr.add(0x10); // &InLoadOrderModuleList (the head sentinel)
    let mut flink: *const u8 = *(list_head as *const *const u8);

    // LDR_DATA_TABLE_ENTRY offsets (x64):
    //   +0x000  InLoadOrderLinks.Flink  (*LDR_DATA_TABLE_ENTRY)
    //   +0x030  DllBase                 (PVOID)
    //   +0x058  BaseDllName.Length      (USHORT)  – byte count, not char count
    //   +0x060  BaseDllName.Buffer      (PWSTR)
    loop {
        // Stop when we've looped back to the head (empty or fully iterated).
        if flink == list_head || flink.is_null() {
            break;
        }

        let dll_base: *const u8 = *(flink.add(0x30) as *const *const u8);
        let name_len: u16 = *(flink.add(0x58) as *const u16); // bytes
        let name_buf: *const u16 = *(flink.add(0x60) as *const *const u16);

        if name_len > 0 && !name_buf.is_null() && !dll_base.is_null() {
            let wchars = std::slice::from_raw_parts(name_buf, (name_len / 2) as usize);
            // Compare in a case-insensitive way without allocating.
            if wchars.len() == 10 // "ntdll.dll" is 9 chars + maybe nul? len=9*2=18 bytes
                || wchars.len() == 9
            {
                let lower: String = char::decode_utf16(wchars.iter().copied())
                    .map(|r| r.unwrap_or('\u{FFFD}').to_ascii_lowercase())
                    .collect();
                if lower == "ntdll.dll" {
                    return Some(dll_base);
                }
            } else {
                // Fallback: build the full string and compare.
                let lower: String = char::decode_utf16(wchars.iter().copied())
                    .map(|r| r.unwrap_or('\u{FFFD}').to_ascii_lowercase())
                    .collect();
                if lower == "ntdll.dll" {
                    return Some(dll_base);
                }
            }
        }

        flink = *(flink as *const *const u8);
    }

    None
}

// ── PE export table walk ──────────────────────────────────────────────────────

/// Return the virtual address of `fn_name` inside the PE image at `base`.
///
/// # Safety
/// `base` must point to a valid, mapped PE image.
unsafe fn find_export(base: *const u8, fn_name: &str) -> Option<*const u8> {
    // DOS header: e_lfanew at +0x3C.
    let e_lfanew = u32::from_le_bytes(
        std::slice::from_raw_parts(base.add(0x3C), 4)
            .try_into()
            .ok()?,
    ) as usize;

    // Verify "PE\0\0" signature.
    let sig = u32::from_le_bytes(
        std::slice::from_raw_parts(base.add(e_lfanew), 4)
            .try_into()
            .ok()?,
    );
    if sig != 0x0000_4550 {
        return None;
    }

    // IMAGE_NT_HEADERS64:
    //   +0x00  Signature       (4 bytes)
    //   +0x04  FileHeader      (IMAGE_FILE_HEADER, 20 bytes)
    //   +0x18  OptionalHeader  (IMAGE_OPTIONAL_HEADER64)
    //
    // IMAGE_OPTIONAL_HEADER64.DataDirectory[0] (Export Directory) is at
    // optional-header-offset + 0x70:
    //   struct IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; }
    let opt_hdr = base.add(e_lfanew + 0x18);
    let export_rva = u32::from_le_bytes(
        std::slice::from_raw_parts(opt_hdr.add(0x70), 4)
            .try_into()
            .ok()?,
    ) as usize;
    if export_rva == 0 {
        return None;
    }

    let exp_dir = base.add(export_rva);

    // IMAGE_EXPORT_DIRECTORY:
    //   +0x14  NumberOfFunctions  (DWORD)
    //   +0x18  NumberOfNames      (DWORD)
    //   +0x1C  AddressOfFunctions (RVA → DWORD[])
    //   +0x20  AddressOfNames     (RVA → DWORD[])
    //   +0x24  AddressOfNameOrdinals (RVA → WORD[])
    let num_names = u32::from_le_bytes(
        std::slice::from_raw_parts(exp_dir.add(0x18), 4)
            .try_into()
            .ok()?,
    ) as usize;
    let funcs_rva = u32::from_le_bytes(
        std::slice::from_raw_parts(exp_dir.add(0x1C), 4)
            .try_into()
            .ok()?,
    ) as usize;
    let names_rva = u32::from_le_bytes(
        std::slice::from_raw_parts(exp_dir.add(0x20), 4)
            .try_into()
            .ok()?,
    ) as usize;
    let ords_rva = u32::from_le_bytes(
        std::slice::from_raw_parts(exp_dir.add(0x24), 4)
            .try_into()
            .ok()?,
    ) as usize;

    let names_arr = base.add(names_rva) as *const u32;
    let ords_arr = base.add(ords_rva) as *const u16;
    let funcs_arr = base.add(funcs_rva) as *const u32;

    for i in 0..num_names {
        let name_rva = *names_arr.add(i) as usize;
        let cname = std::ffi::CStr::from_ptr(base.add(name_rva) as *const i8);
        if let Ok(s) = cname.to_str() {
            if s == fn_name {
                let ord = *ords_arr.add(i) as usize;
                let fn_rva = *funcs_arr.add(ord) as usize;
                return Some(base.add(fn_rva));
            }
        }
    }

    None
}

// ── Syscall-number extraction ─────────────────────────────────────────────────

/// Extract the syscall number from a Windows NT stub using Hell's Gate.
///
/// A clean (unhooked) Windows x64 NT syscall stub begins with:
/// ```text
/// 4C 8B D1        mov r10, rcx
/// B8 XX XX XX XX  mov eax, <syscall_number>
/// ```
/// The syscall number is a 32-bit value at bytes [4..8], but only the low 16
/// bits are ever non-zero in practice.
///
/// If the first byte is `0xE9` (JMP – an EDR hook), **Halo's Gate** is used:
/// neighbouring stubs share sequential syscall numbers, so scanning ±N adjacent
/// stubs (spaced 0x20 bytes apart) recovers the correct number.
unsafe fn extract_syscall_nr(stub: *const u8) -> Option<u16> {
    // ── Hell's Gate: clean stub ───────────────────────────────────────────────
    if *stub == 0x4C && *stub.add(1) == 0x8B && *stub.add(2) == 0xD1 && *stub.add(3) == 0xB8 {
        let nr = u32::from_le_bytes([
            *stub.add(4),
            *stub.add(5),
            *stub.add(6),
            *stub.add(7),
        ]) as u16;
        return Some(nr);
    }

    // ── Halo's Gate: hooked stub – scan neighbours ────────────────────────────
    // NT stubs in ntdll are typically 0x20 or 0x24 bytes and arranged in order;
    // their syscall numbers are monotonically increasing.  Try both spacings.
    for stub_size in [0x20usize, 0x24usize] {
        for delta in 1i32..=32 {
            for &dir in &[1i32, -1i32] {
                let offset = delta * dir * stub_size as i32;
                // Guard against wild pointer dereference with a sanity bound.
                if offset.abs() > 0x800 {
                    continue;
                }
                let neighbor = stub.offset(offset as isize);
                if *neighbor == 0x4C
                    && *neighbor.add(1) == 0x8B
                    && *neighbor.add(2) == 0xD1
                    && *neighbor.add(3) == 0xB8
                {
                    let neighbor_nr = u32::from_le_bytes([
                        *neighbor.add(4),
                        *neighbor.add(5),
                        *neighbor.add(6),
                        *neighbor.add(7),
                    ]) as u16;
                    // Adjust: if neighbor is `delta` stubs AFTER us, its nr is
                    // `delta` higher, so subtract; and vice-versa.
                    let adjusted = if dir > 0 {
                        neighbor_nr.checked_sub(delta as u16)?
                    } else {
                        neighbor_nr.checked_add(delta as u16)?
                    };
                    return Some(adjusted);
                }
            }
        }
    }

    None
}

// ── Public resolver ───────────────────────────────────────────────────────────

/// Resolve (and cache) the syscall number for a named NT function.
///
/// Returns `None` if ntdll cannot be located or the function is not exported.
pub fn resolve(fn_name: &'static str) -> Option<u16> {
    // Fast path: already cached.
    {
        if let Ok(cache) = nr_cache().lock() {
            if let Some(&nr) = cache.get(fn_name) {
                return Some(nr);
            }
        }
    }

    // Slow path: parse ntdll in-memory.
    let nr = unsafe {
        let base = ntdll_base()?;
        let stub = find_export(base, fn_name)?;
        extract_syscall_nr(stub)?
    };

    if let Ok(mut cache) = nr_cache().lock() {
        cache.insert(fn_name, nr);
    }
    Some(nr)
}

// ── Direct syscall primitives ─────────────────────────────────────────────────

/// Direct syscall with 4 register arguments.
///
/// Windows x64 syscall convention:
/// - `rax` = syscall number  
/// - `r10` = arg0 (caller moves rcx → r10 because `syscall` clobbers rcx)
/// - `rdx` = arg1, `r8` = arg2, `r9` = arg3
/// - On return: `rax` = NTSTATUS, `rcx` = clobbered (= next-instruction RIP),
///   `r11` = clobbered (= saved RFLAGS)
#[inline]
pub unsafe fn syscall4(nr: u16, a0: usize, a1: usize, a2: usize, a3: usize) -> i32 {
    let mut rax: u64 = nr as u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") rax,  // in: syscall nr, out: NTSTATUS
        in("r10") a0,          // arg0 (Windows: r10, not rcx)
        in("rdx") a1,          // arg1
        in("r8")  a2,          // arg2
        in("r9")  a3,          // arg3
        lateout("rcx") _,      // clobbered: syscall saves RIP here
        lateout("r11") _,      // clobbered: syscall saves RFLAGS here
        options(nostack),
    );
    rax as i32
}

/// Direct syscall with 3 register arguments.
#[inline]
pub unsafe fn syscall3(nr: u16, a0: usize, a1: usize, a2: usize) -> i32 {
    syscall4(nr, a0, a1, a2, 0)
}

/// Direct syscall with 1 register argument.
#[inline]
pub unsafe fn syscall1(nr: u16, a0: usize) -> i32 {
    syscall4(nr, a0, 0, 0, 0)
}

/// Direct syscall with 7 arguments (4 in registers + 3 on the stack).
///
/// Stack layout before `syscall`:
/// ```text
/// [rsp+0x00]  shadow space (32 bytes)
/// [rsp+0x20]  arg4
/// [rsp+0x28]  arg5
/// [rsp+0x30]  arg6
/// ```
#[inline]
pub unsafe fn syscall7(
    nr: u16,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> i32 {
    let mut rax: u64 = nr as u64;
    core::arch::asm!(
        // Allocate shadow space (0x20) + 3 stack args (0x18) = 0x38.
        // Use 0x40 to maintain 16-byte stack alignment.
        "sub rsp, 0x40",
        "mov qword ptr [rsp+0x20], {a4}",
        "mov qword ptr [rsp+0x28], {a5}",
        "mov qword ptr [rsp+0x30], {a6}",
        "syscall",
        "add rsp, 0x40",
        inlateout("rax") rax,
        in("r10") a0,
        in("rdx") a1,
        in("r8")  a2,
        in("r9")  a3,
        a4 = in(reg) a4,
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        lateout("rcx") _,
        lateout("r11") _,
        // Note: intentionally no `nostack` — we modify rsp.
    );
    rax as i32
}

// ── NT function wrappers ──────────────────────────────────────────────────────

/// `NtQuerySystemInformation` via direct syscall.
///
/// Used for:
/// - class 11  (`SystemModuleInformation`)  → loaded driver list
/// - class 0x9F (`SystemHypervisorDetailInformation`) → hypervisor presence
/// - class 140  (`SystemBootEnvironmentInformation`) → boot firmware info
pub unsafe fn nt_query_system_information(
    system_information_class: u32,
    system_information: *mut u8,
    system_information_length: u32,
    return_length: *mut u32,
) -> i32 {
    let nr = match resolve("NtQuerySystemInformation") {
        Some(n) => n,
        None => return 0xC000_0001_u32 as i32, // STATUS_UNSUCCESSFUL
    };
    syscall4(
        nr,
        system_information_class as usize,
        system_information as usize,
        system_information_length as usize,
        return_length as usize,
    )
}

/// NT `UNICODE_STRING` (must match ntdll's layout exactly on x64).
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    _pad: u32,
    pub buffer: *const u16,
}

/// NT `OBJECT_ATTRIBUTES` (must match ntdll's layout exactly on x64).
#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: usize,           // HANDLE
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: usize,
    pub security_quality_of_service: usize,
}

impl ObjectAttributes {
    /// Initialise an OBJECT_ATTRIBUTES for a named NT object (no root, case-insensitive).
    pub fn new_named(name: &mut UnicodeString) -> Self {
        Self {
            length: std::mem::size_of::<Self>() as u32,
            root_directory: 0,
            object_name: name as *mut _,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: 0,
            security_quality_of_service: 0,
        }
    }
}

/// Initialise a `UnicodeString` from a null-terminated wide-char slice.
///
/// # Safety
/// `wide` must remain valid for as long as the `UnicodeString` is in use.
pub unsafe fn init_unicode_string(wide: &[u16]) -> UnicodeString {
    // Length field is in bytes, does NOT include the null terminator.
    let byte_len = (wide.len().saturating_sub(1) * 2) as u16;
    UnicodeString {
        length: byte_len,
        maximum_length: byte_len + 2,
        _pad: 0,
        buffer: wide.as_ptr(),
    }
}

/// `NtOpenDirectoryObject` via direct syscall.
///
/// Opens a named NT object directory (e.g. `\Device`).
pub unsafe fn nt_open_directory_object(
    directory_handle: *mut usize,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
) -> i32 {
    let nr = match resolve("NtOpenDirectoryObject") {
        Some(n) => n,
        None => return 0xC000_0001_u32 as i32,
    };
    syscall3(
        nr,
        directory_handle as usize,
        desired_access as usize,
        object_attributes as usize,
    )
}

/// `NtQueryDirectoryObject` via direct syscall.
///
/// Enumerates entries in an NT object directory opened with
/// `NtOpenDirectoryObject`.
#[allow(clippy::too_many_arguments)]
pub unsafe fn nt_query_directory_object(
    directory_handle: usize,
    buffer: *mut u8,
    length: u32,
    return_single_entry: u8,
    restart_scan: u8,
    context: *mut u32,
    return_length: *mut u32,
) -> i32 {
    let nr = match resolve("NtQueryDirectoryObject") {
        Some(n) => n,
        None => return 0xC000_0001_u32 as i32,
    };
    syscall7(
        nr,
        directory_handle,
        buffer as usize,
        length as usize,
        return_single_entry as usize,
        restart_scan as usize,
        context as usize,
        return_length as usize,
    )
}

/// `NtClose` via direct syscall.
pub unsafe fn nt_close(handle: usize) -> i32 {
    let nr = match resolve("NtClose") {
        Some(n) => n,
        None => return 0xC000_0001_u32 as i32,
    };
    syscall1(nr, handle)
}
