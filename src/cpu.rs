//! CPU identification utilities: CPUID wrapper, brand string, databases,
//! vmid template, stepping extraction.

use crate::types::VMBrand;

// ── Leaf-result cache ─────────────────────────────────────────────────────────
// 64-slot rolling array of (leaf, result).
const LEAF_CACHE_SIZE: usize = 64;

use std::sync::Mutex;
static LEAF_CACHE: Mutex<[(u32, bool); LEAF_CACHE_SIZE]> =
    Mutex::new([(u32::MAX, false); LEAF_CACHE_SIZE]);
static LEAF_CACHE_IDX: Mutex<usize> = Mutex::new(0);

// ── CPUID result structure ────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Execute CPUID for (leaf, subleaf). Returns zeros on non-x86 platforms.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    let r = raw_cpuid::native_cpuid::cpuid_count(leaf, subleaf);
    CpuidResult {
        eax: r.eax,
        ebx: r.ebx,
        ecx: r.ecx,
        edx: r.edx,
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn cpuid(_leaf: u32, _subleaf: u32) -> CpuidResult {
    CpuidResult::default()
}

/// Check whether CPUID leaf `leaf` is supported by this CPU.
pub fn is_leaf_supported(leaf: u32) -> bool {
    // Check cache first
    {
        let cache = LEAF_CACHE.lock().unwrap();
        for &(l, v) in cache.iter() {
            if l == leaf {
                return v;
            }
        }
    }

    // Query CPUID max leaf
    let max_leaf = if leaf >= 0x8000_0000 {
        cpuid(0x8000_0000, 0).eax
    } else if leaf >= 0x4000_0000 {
        cpuid(0x4000_0000, 0).eax
    } else {
        cpuid(0, 0).eax
    };

    let result = leaf <= max_leaf;

    // Store in cache
    let mut cache = LEAF_CACHE.lock().unwrap();
    let mut idx = LEAF_CACHE_IDX.lock().unwrap();
    cache[*idx % LEAF_CACHE_SIZE] = (leaf, result);
    *idx = idx.wrapping_add(1);

    result
}

/// Returns true if the CPU manufacturer is Intel.
pub fn is_intel() -> bool {
    let r = cpuid(0, 0);
    // "GenuineIntel" in EBX/EDX/ECX
    r.ebx == 0x756e_6547 && r.edx == 0x4965_6e69 && r.ecx == 0x6c65_746e
}

/// Returns true if the CPU manufacturer is AMD.
pub fn is_amd() -> bool {
    let r = cpuid(0, 0);
    // "AuthenticAMD" in EBX/EDX/ECX
    r.ebx == 0x6874_7541 && r.edx == 0x6974_6e65 && r.ecx == 0x444d_4163
}

/// Reconstruct a 12-byte vendor string from EBX/ECX/EDX of a CPUID result.
pub fn vendor_string(ebx: u32, ecx: u32, edx: u32) -> String {
    let mut bytes = [0u8; 12];
    bytes[0..4].copy_from_slice(&ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&edx.to_le_bytes());
    bytes[8..12].copy_from_slice(&ecx.to_le_bytes());
    String::from_utf8_lossy(&bytes).to_string()
}

/// Return the CPU brand string (from leaves 0x80000002-4). Empty on failure.
pub fn cpu_brand_string() -> String {
    if !is_leaf_supported(0x8000_0004) {
        return String::new();
    }
    let mut brand = [0u8; 48];
    for (i, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
        let r = cpuid(leaf, 0);
        let off = i * 16;
        brand[off..off + 4].copy_from_slice(&r.eax.to_le_bytes());
        brand[off + 4..off + 8].copy_from_slice(&r.ebx.to_le_bytes());
        brand[off + 8..off + 12].copy_from_slice(&r.ecx.to_le_bytes());
        brand[off + 12..off + 16].copy_from_slice(&r.edx.to_le_bytes());
    }
    let s = String::from_utf8_lossy(&brand);
    s.trim_end_matches('\0').trim().to_string()
}

/// CPU stepping information (model, family, ext-model).
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuStepping {
    pub model: u32,
    pub family: u32,
    pub extmodel: u32,
}

/// Extract stepping info from CPUID leaf 1 EAX.
pub fn fetch_steppings() -> CpuStepping {
    let eax = cpuid(1, 0).eax;
    let model = (eax >> 4) & 0xf;
    let family = (eax >> 8) & 0xf;
    let extmodel = (eax >> 16) & 0xf;
    CpuStepping { model, family, extmodel }
}

/// Returns true if the CPU is a Celeron based on its brand string.
pub fn is_celeron(brand: &str) -> bool {
    brand.contains("Celeron")
}

// ── Known hypervisor vendor strings (leaf 0x40000000 EBX/ECX/EDX) ─────────────
/// Matches vendor strings against 30+ known VM signatures.
/// Returns (`found: bool`, `brand: VMBrand`).
pub fn vmid_template(leaf: u32) -> (bool, VMBrand) {
    if !is_leaf_supported(leaf) {
        return (false, VMBrand::Invalid);
    }
    let r = cpuid(leaf, 0);
    let v = vendor_string(r.ebx, r.ecx, r.edx);

    // Table: (substring, brand)
    static TABLE: &[(&str, VMBrand)] = &[
        ("KVMKVMKVM",      VMBrand::KVM),
        ("Microsoft Hv",   VMBrand::HyperV),
        ("VMwareVMware",   VMBrand::VMware),
        ("XenVMMXenVMM",   VMBrand::Xen),
        ("prl hyperv",     VMBrand::Parallels),
        ("prl hv",         VMBrand::Parallels),
        ("VBoxVBoxVBox",   VMBrand::VBox),
        (" lrpepyh  vr",   VMBrand::Parallels),   // "prl hyperv" scrambled
        ("bhyve bhyve",    VMBrand::Bhyve),
        ("ACRNACRNACRN",   VMBrand::ACRN),
        ("QNXQVMBSQG",     VMBrand::QNX),
        ("GenuineIntel",   VMBrand::Invalid),      // not a VM id
        ("AuthenticAMD",   VMBrand::Invalid),
        ("HygonGenuine",   VMBrand::Invalid),
        (" KVMH",          VMBrand::KVMHyperV),
        ("QEMU",           VMBrand::QEMU),
        ("Jailhouse",      VMBrand::Jailhouse),
        ("Apple VZ",       VMBrand::AppleVZ),
        ("UnisysSpar64",   VMBrand::Unisys),
        ("LMHS",           VMBrand::LMHS),
        ("NoirVisor",      VMBrand::NoirVisor),
        ("SimpleVisor",    VMBrand::SimpleVisor),
        ("Barevisor",      VMBrand::Barevisor),
        ("HyperPlatform",  VMBrand::HyperPlatform),
        ("MiniVisor",      VMBrand::MiniVisor),
        ("DBVM",           VMBrand::DBVM),
        ("Intel TDX",      VMBrand::IntelTDX),
        ("VirtualApple",   VMBrand::UTM),
    ];

    for &(sig, brand) in TABLE {
        if v.contains(sig) {
            if brand == VMBrand::Invalid {
                return (false, VMBrand::Invalid);
            }
            return (true, brand);
        }
    }

    // KGT (Intel Kernel Guard Technology) uses leaf 0x40000001
    if leaf == 0x4000_0001 {
        let eax = r.eax;
        if eax == 0x4d_494b54 {
            // "TKIM"
            return (true, VMBrand::IntelKGT);
        }
    }

    (false, VMBrand::Invalid)
}

// ── CPU thread-count databases ─────────────────────────────────────────────────
// Each (model substring, logical thread count) entry
pub struct CpuEntry {
    pub model: &'static str,
    pub threads: u32,
}

/// Intel Core i3/i5/i7/i9 database.
pub static INTEL_CORE_DB: &[CpuEntry] = &[
    CpuEntry { model: "i3-1000G1",  threads: 4  },
    CpuEntry { model: "i3-1000G4",  threads: 4  },
    CpuEntry { model: "i3-10100",   threads: 8  },
    CpuEntry { model: "i3-10100E",  threads: 8  },
    CpuEntry { model: "i3-10100F",  threads: 8  },
    CpuEntry { model: "i3-10100T",  threads: 8  },
    CpuEntry { model: "i3-10100TE", threads: 8  },
    CpuEntry { model: "i3-10105",   threads: 8  },
    CpuEntry { model: "i3-10105F",  threads: 8  },
    CpuEntry { model: "i3-10105T",  threads: 8  },
    CpuEntry { model: "i3-10110U",  threads: 4  },
    CpuEntry { model: "i3-10110Y",  threads: 4  },
    CpuEntry { model: "i3-10300",   threads: 8  },
    CpuEntry { model: "i3-10300T",  threads: 8  },
    CpuEntry { model: "i3-10305",   threads: 8  },
    CpuEntry { model: "i3-10305T",  threads: 8  },
    CpuEntry { model: "i3-10320",   threads: 8  },
    CpuEntry { model: "i3-10325",   threads: 8  },
    CpuEntry { model: "i3-1110G4",  threads: 4  },
    CpuEntry { model: "i3-1115G4E", threads: 4  },
    CpuEntry { model: "i3-1115GRE", threads: 4  },
    CpuEntry { model: "i3-1115G4",  threads: 4  },
    CpuEntry { model: "i3-1120G4",  threads: 8  },
    CpuEntry { model: "i3-1125G4",  threads: 8  },
    CpuEntry { model: "i3-12100",   threads: 8  },
    CpuEntry { model: "i3-12100F",  threads: 8  },
    CpuEntry { model: "i3-12100T",  threads: 8  },
    CpuEntry { model: "i3-12300",   threads: 8  },
    CpuEntry { model: "i3-12300T",  threads: 8  },
    CpuEntry { model: "i3-1210U",   threads: 8  },
    CpuEntry { model: "i3-1215U",   threads: 8  },
    CpuEntry { model: "i3-1215UE",  threads: 8  },
    CpuEntry { model: "i3-1215UL",  threads: 8  },
    CpuEntry { model: "i3-1220P",   threads: 12 },
    CpuEntry { model: "i3-13100",   threads: 8  },
    CpuEntry { model: "i3-13100F",  threads: 8  },
    CpuEntry { model: "i3-13100T",  threads: 8  },
    CpuEntry { model: "i3-1315U",   threads: 8  },
    CpuEntry { model: "i3-1315UE",  threads: 8  },
    CpuEntry { model: "i3-14100",   threads: 8  },
    CpuEntry { model: "i3-14100F",  threads: 8  },
    CpuEntry { model: "i3-14100T",  threads: 8  },
    CpuEntry { model: "i5-10200H",  threads: 8  },
    CpuEntry { model: "i5-10210U",  threads: 8  },
    CpuEntry { model: "i5-10210Y",  threads: 8  },
    CpuEntry { model: "i5-10300H",  threads: 8  },
    CpuEntry { model: "i5-10310U",  threads: 8  },
    CpuEntry { model: "i5-10400",   threads: 12 },
    CpuEntry { model: "i5-10400F",  threads: 12 },
    CpuEntry { model: "i5-10400H",  threads: 8  },
    CpuEntry { model: "i5-10400T",  threads: 12 },
    CpuEntry { model: "i5-10500",   threads: 12 },
    CpuEntry { model: "i5-10500H",  threads: 12 },
    CpuEntry { model: "i5-10500T",  threads: 12 },
    CpuEntry { model: "i5-10500TE", threads: 12 },
    CpuEntry { model: "i5-10505",   threads: 12 },
    CpuEntry { model: "i5-10600",   threads: 12 },
    CpuEntry { model: "i5-10600K",  threads: 12 },
    CpuEntry { model: "i5-10600KF", threads: 12 },
    CpuEntry { model: "i5-10600T",  threads: 12 },
    CpuEntry { model: "i5-1030G4",  threads: 8  },
    CpuEntry { model: "i5-1030G7",  threads: 8  },
    CpuEntry { model: "i5-1035G1",  threads: 8  },
    CpuEntry { model: "i5-1035G4",  threads: 8  },
    CpuEntry { model: "i5-1035G7",  threads: 8  },
    CpuEntry { model: "i5-1130G7",  threads: 8  },
    CpuEntry { model: "i5-1135G7",  threads: 8  },
    CpuEntry { model: "i5-11260H",  threads: 12 },
    CpuEntry { model: "i5-11300H",  threads: 8  },
    CpuEntry { model: "i5-11320H",  threads: 8  },
    CpuEntry { model: "i5-11400",   threads: 12 },
    CpuEntry { model: "i5-11400F",  threads: 12 },
    CpuEntry { model: "i5-11400H",  threads: 12 },
    CpuEntry { model: "i5-11400T",  threads: 12 },
    CpuEntry { model: "i5-11500",   threads: 12 },
    CpuEntry { model: "i5-11500H",  threads: 12 },
    CpuEntry { model: "i5-11500T",  threads: 12 },
    CpuEntry { model: "i5-11600",   threads: 12 },
    CpuEntry { model: "i5-11600K",  threads: 12 },
    CpuEntry { model: "i5-11600KF", threads: 12 },
    CpuEntry { model: "i5-11600T",  threads: 12 },
    CpuEntry { model: "i5-1230U",   threads: 12 },
    CpuEntry { model: "i5-1235U",   threads: 12 },
    CpuEntry { model: "i5-1235UL",  threads: 12 },
    CpuEntry { model: "i5-12400",   threads: 12 },
    CpuEntry { model: "i5-12400F",  threads: 12 },
    CpuEntry { model: "i5-12400T",  threads: 12 },
    CpuEntry { model: "i5-12450H",  threads: 12 },
    CpuEntry { model: "i5-12450HX", threads: 12 },
    CpuEntry { model: "i5-12500",   threads: 12 },
    CpuEntry { model: "i5-12500H",  threads: 16 },
    CpuEntry { model: "i5-12500T",  threads: 12 },
    CpuEntry { model: "i5-12600",   threads: 12 },
    CpuEntry { model: "i5-12600H",  threads: 16 },
    CpuEntry { model: "i5-12600HX", threads: 16 },
    CpuEntry { model: "i5-12600K",  threads: 16 },
    CpuEntry { model: "i5-12600KF", threads: 16 },
    CpuEntry { model: "i5-12600T",  threads: 12 },
    CpuEntry { model: "i5-1240P",   threads: 16 },
    CpuEntry { model: "i5-1240U",   threads: 12 },
    CpuEntry { model: "i5-1245U",   threads: 12 },
    CpuEntry { model: "i5-1245UE",  threads: 12 },
    CpuEntry { model: "i5-1250P",   threads: 16 },
    CpuEntry { model: "i5-1250PE",  threads: 16 },
    CpuEntry { model: "i5-13400",   threads: 16 },
    CpuEntry { model: "i5-13400F",  threads: 16 },
    CpuEntry { model: "i5-13400T",  threads: 16 },
    CpuEntry { model: "i5-13450HX", threads: 16 },
    CpuEntry { model: "i5-13490F",  threads: 16 },
    CpuEntry { model: "i5-13500",   threads: 20 },
    CpuEntry { model: "i5-13500H",  threads: 16 },
    CpuEntry { model: "i5-13500HX", threads: 16 },
    CpuEntry { model: "i5-13500T",  threads: 20 },
    CpuEntry { model: "i5-13600",   threads: 20 },
    CpuEntry { model: "i5-13600H",  threads: 16 },
    CpuEntry { model: "i5-13600HX", threads: 20 },
    CpuEntry { model: "i5-13600K",  threads: 20 },
    CpuEntry { model: "i5-13600KF", threads: 20 },
    CpuEntry { model: "i5-13600T",  threads: 20 },
    CpuEntry { model: "i5-1340P",   threads: 16 },
    CpuEntry { model: "i5-1345U",   threads: 12 },
    CpuEntry { model: "i5-1345UE",  threads: 12 },
    CpuEntry { model: "i5-14400",   threads: 16 },
    CpuEntry { model: "i5-14400F",  threads: 16 },
    CpuEntry { model: "i5-14400T",  threads: 16 },
    CpuEntry { model: "i5-14500",   threads: 20 },
    CpuEntry { model: "i5-14500HX", threads: 20 },
    CpuEntry { model: "i5-14500T",  threads: 20 },
    CpuEntry { model: "i5-14600",   threads: 20 },
    CpuEntry { model: "i5-14600K",  threads: 20 },
    CpuEntry { model: "i5-14600KF", threads: 20 },
    CpuEntry { model: "i5-14600T",  threads: 20 },
    CpuEntry { model: "i7-10510U",  threads: 8  },
    CpuEntry { model: "i7-10510Y",  threads: 8  },
    CpuEntry { model: "i7-10700",   threads: 16 },
    CpuEntry { model: "i7-10700E",  threads: 16 },
    CpuEntry { model: "i7-10700F",  threads: 16 },
    CpuEntry { model: "i7-10700K",  threads: 16 },
    CpuEntry { model: "i7-10700KF", threads: 16 },
    CpuEntry { model: "i7-10700T",  threads: 16 },
    CpuEntry { model: "i7-10700TE", threads: 16 },
    CpuEntry { model: "i7-10710U",  threads: 12 },
    CpuEntry { model: "i7-10750H",  threads: 12 },
    CpuEntry { model: "i7-10810U",  threads: 12 },
    CpuEntry { model: "i7-10850H",  threads: 12 },
    CpuEntry { model: "i7-10870H",  threads: 16 },
    CpuEntry { model: "i7-10875H",  threads: 16 },
    CpuEntry { model: "i7-1060G7",  threads: 8  },
    CpuEntry { model: "i7-1060NG7", threads: 8  },
    CpuEntry { model: "i7-1065G7",  threads: 8  },
    CpuEntry { model: "i7-1068G7",  threads: 8  },
    CpuEntry { model: "i7-1068NG7", threads: 8  },
    CpuEntry { model: "i7-1160G7",  threads: 8  },
    CpuEntry { model: "i7-1165G7",  threads: 8  },
    CpuEntry { model: "i7-11370H",  threads: 8  },
    CpuEntry { model: "i7-11375H",  threads: 8  },
    CpuEntry { model: "i7-11390H",  threads: 8  },
    CpuEntry { model: "i7-11600H",  threads: 12 },
    CpuEntry { model: "i7-1180G7",  threads: 8  },
    CpuEntry { model: "i7-11800H",  threads: 16 },
    CpuEntry { model: "i7-11850H",  threads: 16 },
    CpuEntry { model: "i7-11850HE", threads: 16 },
    CpuEntry { model: "i7-1185G7",  threads: 8  },
    CpuEntry { model: "i7-1185G7E", threads: 8  },
    CpuEntry { model: "i7-1185GRE", threads: 8  },
    CpuEntry { model: "i7-11700",   threads: 16 },
    CpuEntry { model: "i7-11700F",  threads: 16 },
    CpuEntry { model: "i7-11700K",  threads: 16 },
    CpuEntry { model: "i7-11700KF", threads: 16 },
    CpuEntry { model: "i7-11700T",  threads: 16 },
    CpuEntry { model: "i7-1260P",   threads: 16 },
    CpuEntry { model: "i7-1260U",   threads: 12 },
    CpuEntry { model: "i7-1265U",   threads: 12 },
    CpuEntry { model: "i7-1265UE",  threads: 12 },
    CpuEntry { model: "i7-12650H",  threads: 16 },
    CpuEntry { model: "i7-12700",   threads: 20 },
    CpuEntry { model: "i7-12700F",  threads: 20 },
    CpuEntry { model: "i7-12700H",  threads: 20 },
    CpuEntry { model: "i7-12700K",  threads: 20 },
    CpuEntry { model: "i7-12700KF", threads: 20 },
    CpuEntry { model: "i7-12700T",  threads: 20 },
    CpuEntry { model: "i7-12800H",  threads: 20 },
    CpuEntry { model: "i7-12800HE", threads: 20 },
    CpuEntry { model: "i7-12800HX", threads: 24 },
    CpuEntry { model: "i7-12850HX", threads: 24 },
    CpuEntry { model: "i7-1280P",   threads: 20 },
    CpuEntry { model: "i7-13620H",  threads: 16 },
    CpuEntry { model: "i7-13650HX", threads: 20 },
    CpuEntry { model: "i7-13700",   threads: 24 },
    CpuEntry { model: "i7-13700F",  threads: 24 },
    CpuEntry { model: "i7-13700H",  threads: 20 },
    CpuEntry { model: "i7-13700HX", threads: 24 },
    CpuEntry { model: "i7-13700K",  threads: 24 },
    CpuEntry { model: "i7-13700KF", threads: 24 },
    CpuEntry { model: "i7-13700T",  threads: 24 },
    CpuEntry { model: "i7-1360P",   threads: 16 },
    CpuEntry { model: "i7-1365U",   threads: 12 },
    CpuEntry { model: "i7-1365UE",  threads: 12 },
    CpuEntry { model: "i7-14700",   threads: 28 },
    CpuEntry { model: "i7-14700F",  threads: 28 },
    CpuEntry { model: "i7-14700HX", threads: 28 },
    CpuEntry { model: "i7-14700K",  threads: 28 },
    CpuEntry { model: "i7-14700KF", threads: 28 },
    CpuEntry { model: "i7-14700T",  threads: 28 },
    CpuEntry { model: "i9-10850K",  threads: 20 },
    CpuEntry { model: "i9-10900",   threads: 20 },
    CpuEntry { model: "i9-10900E",  threads: 20 },
    CpuEntry { model: "i9-10900F",  threads: 20 },
    CpuEntry { model: "i9-10900K",  threads: 20 },
    CpuEntry { model: "i9-10900KF", threads: 20 },
    CpuEntry { model: "i9-10900T",  threads: 20 },
    CpuEntry { model: "i9-10900TE", threads: 20 },
    CpuEntry { model: "i9-10900X",  threads: 20 },
    CpuEntry { model: "i9-10940X",  threads: 28 },
    CpuEntry { model: "i9-10980HK", threads: 16 },
    CpuEntry { model: "i9-10980XE", threads: 36 },
    CpuEntry { model: "i9-11900",   threads: 16 },
    CpuEntry { model: "i9-11900F",  threads: 16 },
    CpuEntry { model: "i9-11900H",  threads: 16 },
    CpuEntry { model: "i9-11900K",  threads: 16 },
    CpuEntry { model: "i9-11900KB", threads: 16 },
    CpuEntry { model: "i9-11900KF", threads: 16 },
    CpuEntry { model: "i9-11900T",  threads: 16 },
    CpuEntry { model: "i9-11950H",  threads: 16 },
    CpuEntry { model: "i9-11980HK", threads: 16 },
    CpuEntry { model: "i9-12900",   threads: 24 },
    CpuEntry { model: "i9-12900F",  threads: 24 },
    CpuEntry { model: "i9-12900H",  threads: 20 },
    CpuEntry { model: "i9-12900HK", threads: 20 },
    CpuEntry { model: "i9-12900HX", threads: 32 },
    CpuEntry { model: "i9-12900K",  threads: 24 },
    CpuEntry { model: "i9-12900KF", threads: 24 },
    CpuEntry { model: "i9-12900KS", threads: 24 },
    CpuEntry { model: "i9-12900T",  threads: 24 },
    CpuEntry { model: "i9-13900",   threads: 32 },
    CpuEntry { model: "i9-13900E",  threads: 32 },
    CpuEntry { model: "i9-13900F",  threads: 32 },
    CpuEntry { model: "i9-13900H",  threads: 20 },
    CpuEntry { model: "i9-13900HK", threads: 20 },
    CpuEntry { model: "i9-13900HX", threads: 32 },
    CpuEntry { model: "i9-13900K",  threads: 32 },
    CpuEntry { model: "i9-13900KF", threads: 32 },
    CpuEntry { model: "i9-13900KS", threads: 32 },
    CpuEntry { model: "i9-13900T",  threads: 32 },
    CpuEntry { model: "i9-13900TE", threads: 32 },
    CpuEntry { model: "i9-13950HX", threads: 32 },
    CpuEntry { model: "i9-13980HX", threads: 32 },
    CpuEntry { model: "i9-14900",   threads: 32 },
    CpuEntry { model: "i9-14900F",  threads: 32 },
    CpuEntry { model: "i9-14900HX", threads: 32 },
    CpuEntry { model: "i9-14900K",  threads: 32 },
    CpuEntry { model: "i9-14900KF", threads: 32 },
    CpuEntry { model: "i9-14900KS", threads: 32 },
    CpuEntry { model: "i9-14900T",  threads: 32 },
];

/// Intel Xeon D/E/W series database.
pub static INTEL_XEON_DB: &[CpuEntry] = &[
    CpuEntry { model: "Xeon D-1513N",  threads: 10 },
    CpuEntry { model: "Xeon D-1523N",  threads: 8  },
    CpuEntry { model: "Xeon D-1533N",  threads: 10 },
    CpuEntry { model: "Xeon D-1543N",  threads: 16 },
    CpuEntry { model: "Xeon D-1553N",  threads: 16 },
    CpuEntry { model: "Xeon D-2123IT", threads: 8  },
    CpuEntry { model: "Xeon D-2141I",  threads: 16 },
    CpuEntry { model: "Xeon D-2143IT", threads: 16 },
    CpuEntry { model: "Xeon D-2145NT", threads: 16 },
    CpuEntry { model: "Xeon D-2146NT", threads: 16 },
    CpuEntry { model: "Xeon D-2161I",  threads: 24 },
    CpuEntry { model: "Xeon D-2163IT", threads: 24 },
    CpuEntry { model: "Xeon D-2166NT", threads: 24 },
    CpuEntry { model: "Xeon D-2173IT", threads: 28 },
    CpuEntry { model: "Xeon D-2177NT", threads: 28 },
    CpuEntry { model: "Xeon D-2183IT", threads: 32 },
    CpuEntry { model: "Xeon D-2187NT", threads: 32 },
    CpuEntry { model: "Xeon E-2224",   threads: 4  },
    CpuEntry { model: "Xeon E-2224G",  threads: 4  },
    CpuEntry { model: "Xeon E-2226G",  threads: 6  },
    CpuEntry { model: "Xeon E-2226GE", threads: 6  },
    CpuEntry { model: "Xeon E-2234",   threads: 8  },
    CpuEntry { model: "Xeon E-2236",   threads: 12 },
    CpuEntry { model: "Xeon E-2244G",  threads: 8  },
    CpuEntry { model: "Xeon E-2246G",  threads: 12 },
    CpuEntry { model: "Xeon E-2254ME", threads: 8  },
    CpuEntry { model: "Xeon E-2254ML", threads: 8  },
    CpuEntry { model: "Xeon E-2256G",  threads: 12 },
    CpuEntry { model: "Xeon E-2274G",  threads: 8  },
    CpuEntry { model: "Xeon E-2276G",  threads: 12 },
    CpuEntry { model: "Xeon E-2276ME", threads: 12 },
    CpuEntry { model: "Xeon E-2276ML", threads: 12 },
    CpuEntry { model: "Xeon E-2278G",  threads: 16 },
    CpuEntry { model: "Xeon E-2278GE", threads: 16 },
    CpuEntry { model: "Xeon E-2278GEL", threads: 16},
    CpuEntry { model: "Xeon E-2278MEL", threads: 16},
    CpuEntry { model: "Xeon E-2286G",  threads: 12 },
    CpuEntry { model: "Xeon E-2286M",  threads: 16 },
    CpuEntry { model: "Xeon E-2288G",  threads: 16 },
    CpuEntry { model: "Xeon E-2314",   threads: 4  },
    CpuEntry { model: "Xeon E-2324G",  threads: 4  },
    CpuEntry { model: "Xeon E-2334",   threads: 8  },
    CpuEntry { model: "Xeon E-2336",   threads: 12 },
    CpuEntry { model: "Xeon E-2356G",  threads: 12 },
    CpuEntry { model: "Xeon E-2374G",  threads: 8  },
    CpuEntry { model: "Xeon E-2378",   threads: 16 },
    CpuEntry { model: "Xeon E-2378G",  threads: 16 },
    CpuEntry { model: "Xeon E-2386G",  threads: 12 },
    CpuEntry { model: "Xeon E-2388G",  threads: 16 },
    CpuEntry { model: "Xeon W-1250",   threads: 12 },
    CpuEntry { model: "Xeon W-1250E",  threads: 12 },
    CpuEntry { model: "Xeon W-1250P",  threads: 12 },
    CpuEntry { model: "Xeon W-1250TE", threads: 12 },
    CpuEntry { model: "Xeon W-1270",   threads: 16 },
    CpuEntry { model: "Xeon W-1270E",  threads: 16 },
    CpuEntry { model: "Xeon W-1270P",  threads: 16 },
    CpuEntry { model: "Xeon W-1270TE", threads: 16 },
    CpuEntry { model: "Xeon W-1290",   threads: 20 },
    CpuEntry { model: "Xeon W-1290E",  threads: 20 },
    CpuEntry { model: "Xeon W-1290P",  threads: 20 },
    CpuEntry { model: "Xeon W-1290T",  threads: 20 },
    CpuEntry { model: "Xeon W-1290TE", threads: 20 },
    CpuEntry { model: "Xeon W-1350",   threads: 12 },
    CpuEntry { model: "Xeon W-1350P",  threads: 12 },
    CpuEntry { model: "Xeon W-1370",   threads: 16 },
    CpuEntry { model: "Xeon W-1370P",  threads: 16 },
    CpuEntry { model: "Xeon W-1390",   threads: 20 },
    CpuEntry { model: "Xeon W-1390P",  threads: 20 },
    CpuEntry { model: "Xeon W-1390T",  threads: 20 },
    CpuEntry { model: "Xeon W-3323",   threads: 24 },
    CpuEntry { model: "Xeon W-3335",   threads: 32 },
    CpuEntry { model: "Xeon W-3345",   threads: 48 },
    CpuEntry { model: "Xeon W-3365",   threads: 64 },
    CpuEntry { model: "Xeon W-3375",   threads: 72 },
    CpuEntry { model: "Xeon W-9-3575X", threads: 112},
    CpuEntry { model: "Xeon W-7-2595X", threads: 64},
    CpuEntry { model: "Xeon W-5-3435X", threads: 32},
    CpuEntry { model: "Xeon W-3-2435",  threads: 24},
];

/// Intel Core Ultra (Series 1 / Series 2) database.
pub static INTEL_ULTRA_DB: &[CpuEntry] = &[
    CpuEntry { model: "Ultra 5 125U",  threads: 12 },
    CpuEntry { model: "Ultra 5 125H",  threads: 14 },
    CpuEntry { model: "Ultra 5 135U",  threads: 12 },
    CpuEntry { model: "Ultra 5 135H",  threads: 14 },
    CpuEntry { model: "Ultra 5 138U",  threads: 12 },
    CpuEntry { model: "Ultra 5 225",   threads: 14 },
    CpuEntry { model: "Ultra 5 226V",  threads: 8  },
    CpuEntry { model: "Ultra 5 245",   threads: 14 },
    CpuEntry { model: "Ultra 5 245K",  threads: 14 },
    CpuEntry { model: "Ultra 7 155U",  threads: 12 },
    CpuEntry { model: "Ultra 7 155H",  threads: 22 },
    CpuEntry { model: "Ultra 7 165U",  threads: 12 },
    CpuEntry { model: "Ultra 7 165H",  threads: 22 },
    CpuEntry { model: "Ultra 7 165UX", threads: 12 },
    CpuEntry { model: "Ultra 7 255U",  threads: 12 },
    CpuEntry { model: "Ultra 7 258V",  threads: 8  },
    CpuEntry { model: "Ultra 7 265",   threads: 20 },
    CpuEntry { model: "Ultra 7 265K",  threads: 20 },
    CpuEntry { model: "Ultra 7 265KF", threads: 20 },
    CpuEntry { model: "Ultra 9 185H",  threads: 22 },
    CpuEntry { model: "Ultra 9 285K",  threads: 24 },
];

/// AMD Ryzen / Threadripper database.
pub static AMD_RYZEN_DB: &[CpuEntry] = &[
    CpuEntry { model: "Ryzen 3 2200G",     threads: 4  },
    CpuEntry { model: "Ryzen 3 2300X",     threads: 4  },
    CpuEntry { model: "Ryzen 3 3100",      threads: 8  },
    CpuEntry { model: "Ryzen 3 3200G",     threads: 4  },
    CpuEntry { model: "Ryzen 3 3200U",     threads: 4  },
    CpuEntry { model: "Ryzen 3 3300U",     threads: 8  },
    CpuEntry { model: "Ryzen 3 3300X",     threads: 8  },
    CpuEntry { model: "Ryzen 3 4100",      threads: 8  },
    CpuEntry { model: "Ryzen 3 4300G",     threads: 8  },
    CpuEntry { model: "Ryzen 3 4300GE",    threads: 8  },
    CpuEntry { model: "Ryzen 3 4300U",     threads: 8  },
    CpuEntry { model: "Ryzen 3 5300G",     threads: 8  },
    CpuEntry { model: "Ryzen 3 5300GE",    threads: 8  },
    CpuEntry { model: "Ryzen 3 5300U",     threads: 8  },
    CpuEntry { model: "Ryzen 3 5400U",     threads: 8  },
    CpuEntry { model: "Ryzen 3 5425C",     threads: 8  },
    CpuEntry { model: "Ryzen 3 5425U",     threads: 8  },
    CpuEntry { model: "Ryzen 3 7320C",     threads: 8  },
    CpuEntry { model: "Ryzen 3 7320U",     threads: 8  },
    CpuEntry { model: "Ryzen 3 7330U",     threads: 8  },
    CpuEntry { model: "Ryzen 5 1400",      threads: 8  },
    CpuEntry { model: "Ryzen 5 1500X",     threads: 8  },
    CpuEntry { model: "Ryzen 5 1600",      threads: 12 },
    CpuEntry { model: "Ryzen 5 1600X",     threads: 12 },
    CpuEntry { model: "Ryzen 5 2400G",     threads: 8  },
    CpuEntry { model: "Ryzen 5 2600",      threads: 12 },
    CpuEntry { model: "Ryzen 5 2600X",     threads: 12 },
    CpuEntry { model: "Ryzen 5 3400G",     threads: 8  },
    CpuEntry { model: "Ryzen 5 3500",      threads: 6  },
    CpuEntry { model: "Ryzen 5 3500U",     threads: 8  },
    CpuEntry { model: "Ryzen 5 3500X",     threads: 6  },
    CpuEntry { model: "Ryzen 5 3600",      threads: 12 },
    CpuEntry { model: "Ryzen 5 3600X",     threads: 12 },
    CpuEntry { model: "Ryzen 5 3600XT",    threads: 12 },
    CpuEntry { model: "Ryzen 5 4500",      threads: 12 },
    CpuEntry { model: "Ryzen 5 4500G",     threads: 12 },
    CpuEntry { model: "Ryzen 5 4500GE",    threads: 12 },
    CpuEntry { model: "Ryzen 5 4500U",     threads: 8  },
    CpuEntry { model: "Ryzen 5 4600G",     threads: 12 },
    CpuEntry { model: "Ryzen 5 4600GE",    threads: 12 },
    CpuEntry { model: "Ryzen 5 4600H",     threads: 12 },
    CpuEntry { model: "Ryzen 5 4600U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 4680U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5500",      threads: 12 },
    CpuEntry { model: "Ryzen 5 5500G",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5500GE",    threads: 12 },
    CpuEntry { model: "Ryzen 5 5500U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5505",      threads: 12 },
    CpuEntry { model: "Ryzen 5 5600",      threads: 12 },
    CpuEntry { model: "Ryzen 5 5600G",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5600GE",    threads: 12 },
    CpuEntry { model: "Ryzen 5 5600H",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5600HS",    threads: 12 },
    CpuEntry { model: "Ryzen 5 5600T",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5600U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5600X",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5600X3D",   threads: 12 },
    CpuEntry { model: "Ryzen 5 5625C",     threads: 12 },
    CpuEntry { model: "Ryzen 5 5625U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 7500F",     threads: 12 },
    CpuEntry { model: "Ryzen 5 7520C",     threads: 8  },
    CpuEntry { model: "Ryzen 5 7520U",     threads: 8  },
    CpuEntry { model: "Ryzen 5 7530U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 7535HS",    threads: 12 },
    CpuEntry { model: "Ryzen 5 7535U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 7540U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 7545U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 7600",      threads: 12 },
    CpuEntry { model: "Ryzen 5 7600X",     threads: 12 },
    CpuEntry { model: "Ryzen 5 7600X3D",   threads: 12 },
    CpuEntry { model: "Ryzen 5 7640HS",    threads: 12 },
    CpuEntry { model: "Ryzen 5 7640U",     threads: 12 },
    CpuEntry { model: "Ryzen 5 7645HX",    threads: 12 },
    CpuEntry { model: "Ryzen 7 1700",      threads: 16 },
    CpuEntry { model: "Ryzen 7 1700X",     threads: 16 },
    CpuEntry { model: "Ryzen 7 1800X",     threads: 16 },
    CpuEntry { model: "Ryzen 7 2700",      threads: 16 },
    CpuEntry { model: "Ryzen 7 2700X",     threads: 16 },
    CpuEntry { model: "Ryzen 7 3700U",     threads: 8  },
    CpuEntry { model: "Ryzen 7 3700X",     threads: 16 },
    CpuEntry { model: "Ryzen 7 3750H",     threads: 8  },
    CpuEntry { model: "Ryzen 7 3800X",     threads: 16 },
    CpuEntry { model: "Ryzen 7 3800XT",    threads: 16 },
    CpuEntry { model: "Ryzen 7 3780U",     threads: 8  },
    CpuEntry { model: "Ryzen 7 4700G",     threads: 16 },
    CpuEntry { model: "Ryzen 7 4700GE",    threads: 16 },
    CpuEntry { model: "Ryzen 7 4700U",     threads: 8  },
    CpuEntry { model: "Ryzen 7 4800H",     threads: 16 },
    CpuEntry { model: "Ryzen 7 4800HS",    threads: 16 },
    CpuEntry { model: "Ryzen 7 4800U",     threads: 16 },
    CpuEntry { model: "Ryzen 7 4980U",     threads: 16 },
    CpuEntry { model: "Ryzen 7 5700G",     threads: 16 },
    CpuEntry { model: "Ryzen 7 5700GE",    threads: 16 },
    CpuEntry { model: "Ryzen 7 5700U",     threads: 16 },
    CpuEntry { model: "Ryzen 7 5700X",     threads: 16 },
    CpuEntry { model: "Ryzen 7 5700X3D",   threads: 16 },
    CpuEntry { model: "Ryzen 7 5800",      threads: 16 },
    CpuEntry { model: "Ryzen 7 5800H",     threads: 16 },
    CpuEntry { model: "Ryzen 7 5800HS",    threads: 16 },
    CpuEntry { model: "Ryzen 7 5800U",     threads: 16 },
    CpuEntry { model: "Ryzen 7 5800X",     threads: 16 },
    CpuEntry { model: "Ryzen 7 5800X3D",   threads: 16 },
    CpuEntry { model: "Ryzen 7 5825C",     threads: 16 },
    CpuEntry { model: "Ryzen 7 5825U",     threads: 16 },
    CpuEntry { model: "Ryzen 7 7700",      threads: 16 },
    CpuEntry { model: "Ryzen 7 7700X",     threads: 16 },
    CpuEntry { model: "Ryzen 7 7730U",     threads: 16 },
    CpuEntry { model: "Ryzen 7 7735HS",    threads: 16 },
    CpuEntry { model: "Ryzen 7 7735U",     threads: 16 },
    CpuEntry { model: "Ryzen 7 7736U",     threads: 16 },
    CpuEntry { model: "Ryzen 7 7745HX",    threads: 16 },
    CpuEntry { model: "Ryzen 7 7800X3D",   threads: 16 },
    CpuEntry { model: "Ryzen 7 7840HS",    threads: 16 },
    CpuEntry { model: "Ryzen 7 7840U",     threads: 16 },
    CpuEntry { model: "Ryzen 9 3900",      threads: 24 },
    CpuEntry { model: "Ryzen 9 3900X",     threads: 24 },
    CpuEntry { model: "Ryzen 9 3900XT",    threads: 24 },
    CpuEntry { model: "Ryzen 9 3950X",     threads: 32 },
    CpuEntry { model: "Ryzen 9 4900H",     threads: 16 },
    CpuEntry { model: "Ryzen 9 4900HS",    threads: 16 },
    CpuEntry { model: "Ryzen 9 5900",      threads: 24 },
    CpuEntry { model: "Ryzen 9 5900X",     threads: 24 },
    CpuEntry { model: "Ryzen 9 5950X",     threads: 32 },
    CpuEntry { model: "Ryzen 9 5900HS",    threads: 16 },
    CpuEntry { model: "Ryzen 9 5900HX",    threads: 16 },
    CpuEntry { model: "Ryzen 9 5980HX",    threads: 16 },
    CpuEntry { model: "Ryzen 9 5980HS",    threads: 16 },
    CpuEntry { model: "Ryzen 9 7900",      threads: 24 },
    CpuEntry { model: "Ryzen 9 7900X",     threads: 24 },
    CpuEntry { model: "Ryzen 9 7900X3D",   threads: 24 },
    CpuEntry { model: "Ryzen 9 7940HS",    threads: 16 },
    CpuEntry { model: "Ryzen 9 7945HX",    threads: 32 },
    CpuEntry { model: "Ryzen 9 7945HX3D",  threads: 32 },
    CpuEntry { model: "Ryzen 9 7950X",     threads: 32 },
    CpuEntry { model: "Ryzen 9 7950X3D",   threads: 32 },
    CpuEntry { model: "Threadripper 2920X",  threads: 24 },
    CpuEntry { model: "Threadripper 2950X",  threads: 32 },
    CpuEntry { model: "Threadripper 2970WX", threads: 48 },
    CpuEntry { model: "Threadripper 2990WX", threads: 64 },
    CpuEntry { model: "Threadripper 3960X",  threads: 48 },
    CpuEntry { model: "Threadripper 3970X",  threads: 64 },
    CpuEntry { model: "Threadripper 3990X",  threads: 128},
    CpuEntry { model: "Threadripper PRO 3945WX", threads: 24},
    CpuEntry { model: "Threadripper PRO 3955WX", threads: 32},
    CpuEntry { model: "Threadripper PRO 3975WX", threads: 64},
    CpuEntry { model: "Threadripper PRO 3995WX", threads: 128},
    CpuEntry { model: "Threadripper PRO 5945WX", threads: 24},
    CpuEntry { model: "Threadripper PRO 5955WX", threads: 32},
    CpuEntry { model: "Threadripper PRO 5965WX", threads: 48},
    CpuEntry { model: "Threadripper PRO 5975WX", threads: 64},
    CpuEntry { model: "Threadripper PRO 5995WX", threads: 128},
    CpuEntry { model: "Threadripper PRO 7965WX", threads: 48},
    CpuEntry { model: "Threadripper PRO 7975WX", threads: 64},
    CpuEntry { model: "Threadripper PRO 7985WX", threads: 128},
    CpuEntry { model: "Threadripper PRO 7995WX", threads: 192},
];

/// Look up the expected thread count for a given CPU brand string.
/// Returns `None` if not found in any database.
pub fn lookup_expected_threads(brand: &str) -> Option<u32> {
    // Intel Core
    for e in INTEL_CORE_DB {
        if brand.contains(e.model) {
            return Some(e.threads);
        }
    }
    // Intel Xeon
    for e in INTEL_XEON_DB {
        if brand.contains(e.model) {
            return Some(e.threads);
        }
    }
    // Intel Ultra
    for e in INTEL_ULTRA_DB {
        if brand.contains(e.model) {
            return Some(e.threads);
        }
    }
    // AMD Ryzen
    for e in AMD_RYZEN_DB {
        if brand.contains(e.model) {
            return Some(e.threads);
        }
    }
    None
}
