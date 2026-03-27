//! Global memoisation layer – mirrors vmaware_memo.c.
//!
//! All technique results, brand detections, CPU info and other computed values
//! are stored here so each expensive check runs at most once per process.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::types::{HyperXState, VMBrand};

// ── Per-technique result cache ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TechResult {
    pub result: bool,
    pub points: u32,
    pub brand: VMBrand,
}

static TECH_CACHE: OnceLock<Mutex<HashMap<u8, TechResult>>> = OnceLock::new();

fn tech_cache() -> std::sync::MutexGuard<'static, HashMap<u8, TechResult>> {
    TECH_CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
}

/// Store a technique result.
pub fn cache_store(tech_id: u8, result: bool, points: u32, brand: VMBrand) {
    tech_cache().insert(tech_id, TechResult { result, points, brand });
}

/// Fetch a cached technique result, if present.
pub fn cache_fetch(tech_id: u8) -> Option<TechResult> {
    tech_cache().get(&tech_id).cloned()
}

/// Check if a technique result is already cached.
pub fn is_cached(tech_id: u8) -> bool {
    tech_cache().contains_key(&tech_id)
}

// ── Single brand cache ────────────────────────────────────────────────────────

static SINGLE_BRAND: OnceLock<Mutex<Option<VMBrand>>> = OnceLock::new();

fn single_brand_cell() -> std::sync::MutexGuard<'static, Option<VMBrand>> {
    SINGLE_BRAND.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

pub fn set_single_brand(b: VMBrand) {
    *single_brand_cell() = Some(b);
}

pub fn get_single_brand() -> Option<VMBrand> {
    *single_brand_cell()
}

// ── Multiple-brand string cache ───────────────────────────────────────────────

static MULTI_BRAND: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn multi_brand_cell() -> std::sync::MutexGuard<'static, Option<String>> {
    MULTI_BRAND.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

pub fn set_multi_brand(s: String) {
    *multi_brand_cell() = Some(s);
}

pub fn get_multi_brand() -> Option<String> {
    multi_brand_cell().clone()
}

// ── Brand list cache ──────────────────────────────────────────────────────────

static BRAND_LIST: OnceLock<Mutex<Vec<VMBrand>>> = OnceLock::new();

fn brand_list_cell() -> std::sync::MutexGuard<'static, Vec<VMBrand>> {
    BRAND_LIST.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap()
}

pub fn set_brand_list(list: Vec<VMBrand>) {
    *brand_list_cell() = list;
}

pub fn get_brand_list() -> Vec<VMBrand> {
    brand_list_cell().clone()
}

pub fn brand_list_is_set() -> bool {
    !brand_list_cell().is_empty()
}

// ── Conclusion string cache ───────────────────────────────────────────────────

static CONCLUSION: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn conclusion_cell() -> std::sync::MutexGuard<'static, Option<String>> {
    CONCLUSION.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

pub fn set_conclusion(s: String) {
    *conclusion_cell() = Some(s);
}

pub fn get_conclusion() -> Option<String> {
    conclusion_cell().clone()
}

// ── CPU brand string cache ────────────────────────────────────────────────────

static CPU_BRAND: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn cpu_brand_cell() -> std::sync::MutexGuard<'static, Option<String>> {
    CPU_BRAND.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

pub fn set_cpu_brand(s: String) {
    *cpu_brand_cell() = Some(s);
}

pub fn get_cpu_brand() -> Option<String> {
    cpu_brand_cell().clone()
}

// ── Thread count cache ────────────────────────────────────────────────────────

static THREAD_COUNT: OnceLock<Mutex<Option<u32>>> = OnceLock::new();

fn thread_count_cell() -> std::sync::MutexGuard<'static, Option<u32>> {
    THREAD_COUNT.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

pub fn set_thread_count(n: u32) {
    *thread_count_cell() = Some(n);
}

pub fn get_thread_count() -> Option<u32> {
    *thread_count_cell()
}

// ── HyperX state cache ────────────────────────────────────────────────────────

static HYPERX_STATE: OnceLock<Mutex<Option<HyperXState>>> = OnceLock::new();

fn hyperx_cell() -> std::sync::MutexGuard<'static, Option<HyperXState>> {
    HYPERX_STATE.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

pub fn set_hyperx_state(s: HyperXState) {
    *hyperx_cell() = Some(s);
}

pub fn get_hyperx_state() -> Option<HyperXState> {
    *hyperx_cell()
}

// ── BIOS info cache ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct BiosInfo {
    pub manufacturer: String,
    pub model: String,
}

static BIOS_INFO: OnceLock<Mutex<Option<BiosInfo>>> = OnceLock::new();

fn bios_cell() -> std::sync::MutexGuard<'static, Option<BiosInfo>> {
    BIOS_INFO.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

pub fn set_bios_info(info: BiosInfo) {
    *bios_cell() = Some(info);
}

pub fn get_bios_info() -> Option<BiosInfo> {
    bios_cell().clone()
}

// ── Hardened result cache ─────────────────────────────────────────────────────

static HARDENED: OnceLock<Mutex<Option<bool>>> = OnceLock::new();

fn hardened_cell() -> std::sync::MutexGuard<'static, Option<bool>> {
    HARDENED.get_or_init(|| Mutex::new(None)).lock().unwrap()
}

pub fn set_hardened(v: bool) {
    *hardened_cell() = Some(v);
}

pub fn get_hardened() -> Option<bool> {
    *hardened_cell()
}

// ── Reset all caches ──────────────────────────────────────────────────────────

/// Clear all memo caches (used internally by core::reset()).
pub fn reset_all() {
    tech_cache().clear();
    *single_brand_cell() = None;
    *multi_brand_cell() = None;
    *brand_list_cell() = Vec::new();
    *conclusion_cell() = None;
    *cpu_brand_cell() = None;
    *thread_count_cell() = None;
    *hyperx_cell() = None;
    *bios_cell() = None;
    *hardened_cell() = None;
}
