/// All known VM / sandbox brands. Repr as usize for array indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(usize)]
pub enum VMBrand {
    #[default]
    Invalid = 0,
    VBox,
    VMware,
    VMwareExpress,
    VMwareESX,
    VMwareGSX,
    VMwareWorkstation,
    VMwareFusion,
    VMwareHard,
    Bhyve,
    KVM,
    QEMU,
    QEMUKVM,
    KVMHyperV,
    QEMUKVMHyperV,
    HyperV,
    HyperVVPC,
    Parallels,
    Xen,
    ACRN,
    QNX,
    Hybrid,
    Sandboxie,
    Docker,
    Wine,
    VPC,
    Anubis,
    JoeBox,
    ThreatExpert,
    CWSandbox,
    Comodo,
    Bochs,
    NVMM,
    BSDVMM,
    IntelHAXM,
    Unisys,
    LMHS,
    Cuckoo,
    BlueStacks,
    Jailhouse,
    AppleVZ,
    IntelKGT,
    AzureHyperV,
    SimpleVisor,
    HyperVRoot,
    UML,
    PowerVM,
    GCE,
    OpenStack,
    KubeVirt,
    AWSNitro,
    Podman,
    WSL,
    OpenVZ,
    Barevisor,
    HyperPlatform,
    MiniVisor,
    IntelTDX,
    LKVM,
    AMDSEV,
    AMDSEVes,
    AMDSEVsnp,
    NekoProject,
    NoirVisor,
    Qihoo,
    NSJail,
    DBVM,
    UTM,
    Compaq,
    Insignia,
    Connectix,
    // sentinel – keep last
    Count,
}

#[rustfmt::skip]
static BRAND_STRINGS: &[&str] = &[
    "Unknown",
    "VirtualBox",
    "VMware",
    "VMware Express",
    "VMware ESX",
    "VMware GSX",
    "VMware Workstation",
    "VMware Fusion",
    "VMware (with VmwareHardenedLoader)",
    "bhyve",
    "KVM",
    "QEMU",
    "QEMU+KVM",
    "KVM Hyper-V Enlightenment",
    "QEMU+KVM Hyper-V Enlightenment",
    "Microsoft Hyper-V",
    "Microsoft Virtual PC/Hyper-V",
    "Parallels",
    "Xen HVM",
    "ACRN",
    "QNX hypervisor",
    "Hybrid Analysis",
    "Sandboxie",
    "Docker",
    "Wine",
    "Virtual PC",
    "Anubis",
    "JoeBox",
    "ThreatExpert",
    "CWSandbox",
    "Comodo",
    "Bochs",
    "NetBSD NVMM",
    "OpenBSD VMM",
    "Intel HAXM",
    "Unisys s-Par",
    "Lockheed Martin LMHS",
    "Cuckoo",
    "BlueStacks",
    "Jailhouse",
    "Apple VZ",
    "Intel KGT (Trusty)",
    "Microsoft Azure Hyper-V",
    "SimpleVisor",
    "Hyper-V artifact (host with Hyper-V enabled)",
    "User-mode Linux",
    "IBM PowerVM",
    "Google Compute Engine (KVM)",
    "OpenStack (KVM)",
    "KubeVirt (KVM)",
    "AWS Nitro System (KVM-based)",
    "Podman",
    "WSL",
    "OpenVZ",
    "Barevisor",
    "HyperPlatform",
    "MiniVisor",
    "Intel TDX",
    "LKVM",
    "AMD SEV",
    "AMD SEV-ES",
    "AMD SEV-SNP",
    "Neko Project II",
    "NoirVisor",
    "Qihoo 360 Sandbox",
    "nsjail",
    "DBVM",
    "UTM",
    "Compaq FX!32",
    "Insignia RealPC",
    "Connectix Virtual PC",
];

impl VMBrand {
    pub fn as_str(self) -> &'static str {
        let idx = self as usize;
        if idx < BRAND_STRINGS.len() {
            BRAND_STRINGS[idx]
        } else {
            "Unknown"
        }
    }
}

/// Technique identifiers (bit indices in a Flagset).
/// Ordering matches the C port's vm_enum_flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Technique {
    // Windows-only
    GpuCapabilities  = 0,
    AcpiSignature    = 1,
    PowerCapabilities = 2,
    DiskSerial       = 3,
    Ivshmem          = 4,
    Drivers          = 5,
    Handles          = 6,
    VirtualProcessors = 7,
    HypervisorQuery  = 8,
    Audio            = 9,
    Display          = 10,
    Dll              = 11,
    VmwareBackdoor   = 12,
    Wine             = 13,
    VirtualRegistry  = 14,
    Mutex            = 15,
    DeviceString     = 16,
    VpcInvalid       = 17,
    VmwareStr        = 18,
    Gamarue          = 19,
    CuckooDir        = 20,
    CuckooPipe       = 21,
    BootLogo         = 22,
    Trap             = 23,
    Ud               = 24,
    Blockstep        = 25,
    DbvmHypercall    = 26,
    KernelObjects    = 27,
    Nvram            = 28,
    Edid             = 29,
    CpuHeuristic     = 30,
    Clock            = 31,
    Msr              = 32,
    KvmInterception  = 33,
    Breakpoint       = 34,
    // Linux + Windows
    SystemRegisters  = 35,
    Firmware         = 36,
    Devices          = 37,
    Azure            = 38,
    // Linux-only
    SmbiosVmBit      = 39,
    Kmsg             = 40,
    Cvendor          = 41,
    QemuFwCfg        = 42,
    Systemd          = 43,
    Ctype            = 44,
    Dockerenv        = 45,
    Dmidecode        = 46,
    Dmesg            = 47,
    Hwmon            = 48,
    LinuxUserHost    = 49,
    VmwareIomem      = 50,
    VmwareIoports    = 51,
    VmwareScsi       = 52,
    VmwareDmesg      = 53,
    QemuVirtualDmi   = 54,
    QemuUsb          = 55,
    HypervisorDir    = 56,
    UmlCpu           = 57,
    VboxModule       = 58,
    SysinfoProc      = 59,
    DmiScan          = 60,
    PodmanFile       = 61,
    WslProc          = 62,
    FileAccessHistory = 63,
    Mac              = 64,
    NsjailPid        = 65,
    BluestacksFolders = 66,
    AmdSevMsr        = 67,
    Temperature      = 68,
    Processes        = 69,
    // Linux + macOS
    ThreadCount      = 70,
    // macOS-only
    MacMemsize       = 71,
    MacIokit         = 72,
    MacSip           = 73,
    IoregGrep        = 74,
    Hwmodel          = 75,
    MacSys           = 76,
    // Cross-platform CPUID
    HypervisorBit    = 77,
    Vmid             = 78,
    ThreadMismatch   = 79,
    Timer            = 80,
    CpuBrand         = 81,
    HypervisorStr    = 82,
    CpuidSignature   = 83,
    BochsCpu         = 84,
    KgtSignature     = 85,
}

impl Technique {
    pub const COUNT: usize = 86;
}

/// A 128-bit bitset for technique flags (two u64 words).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flagset {
    lo: u64,
    hi: u64,
}

impl Flagset {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a Flagset from a slice of Techniques.
    pub fn from_techniques(techs: &[Technique]) -> Self {
        let mut fs = Self::new();
        for &t in techs {
            fs.set(t);
        }
        fs
    }

    /// Enable a technique bit.
    pub fn set(&mut self, t: Technique) {
        let idx = t as u8;
        if idx < 64 {
            self.lo |= 1u64 << idx;
        } else {
            self.hi |= 1u64 << (idx - 64);
        }
    }

    /// Check if a technique bit is enabled.
    pub fn is_set(&self, t: Technique) -> bool {
        let idx = t as u8;
        if idx < 64 {
            (self.lo >> idx) & 1 != 0
        } else {
            (self.hi >> (idx - 64)) & 1 != 0
        }
    }

    /// Returns true if no techniques are set (empty flagset).
    pub fn is_empty(&self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    /// Enable every known technique.
    pub fn all() -> Self {
        // Techniques 0..COUNT
        let mut fs = Self::new();
        let count = Technique::COUNT as u8;
        for idx in 0..count {
            if idx < 64 {
                fs.lo |= 1u64 << idx;
            } else {
                fs.hi |= 1u64 << (idx - 64);
            }
        }
        fs
    }
}

/// Hyper-X classification state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HyperXState {
    #[default]
    Unknown,
    RealVM,
    ArtifactVM,
    Enlightenment,
}

// ── Detection threshold constants ─────────────────────────────────────────────
pub const THRESHOLD_SCORE: u32 = 150;
pub const HIGH_THRESHOLD_SCORE: u32 = 300;
/// Early-exit when VM_SHORTCUT flag is set and threshold is reached.
pub const VM_SHORTCUT: bool = true;
