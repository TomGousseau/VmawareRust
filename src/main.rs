//! VMAware  —  Command-line interface
//!
//! Mirrors the output style of the C port's cli.cpp.

use vmaware::{brand, conclusion, detect, detected_count, hyperx, multi_brand, percentage, VMBrand, HyperXState};

// ── ANSI helpers (no external dep required) ───────────────────────────────────
const RESET:  &str = "\x1b[0m";
const BOLD:   &str = "\x1b[1m";
const GREEN:  &str = "\x1b[32m";
const RED:    &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN:   &str = "\x1b[36m";
const GREY:   &str = "\x1b[90m";

fn main() {
    // ── Header ────────────────────────────────────────────────────────────────
    println!();
    println!("{}{}VMAware - VM Detection Library (Rust port){}", BOLD, CYAN, RESET);
    println!("{}https://github.com/kernelwernel/VMAware{}", GREY, RESET);
    println!("{}{}{}", GREY, "─".repeat(48), RESET);
    println!();

    // ── Run detection ─────────────────────────────────────────────────────────
    let is_vm = detect(None);
    let pct   = percentage(None);
    let main_brand = brand(None);
    let hx    = hyperx();
    let count = detected_count(None);
    let brands = multi_brand(None);

    // ── VM status ─────────────────────────────────────────────────────────────
    let status_colour = if is_vm { RED } else { GREEN };
    let status_text   = if is_vm { "VIRTUAL MACHINE DETECTED" } else { "No virtual machine detected" };

    println!(" {}Status:{} {}{}{}",
        BOLD, RESET, status_colour, BOLD, status_text);
    println!("{} {}", RESET, "");

    // ── Confidence bar ────────────────────────────────────────────────────────
    let bar_filled = (pct as usize * 30) / 100;
    let bar: String = format!(
        "[{}{}{}]",
        "█".repeat(bar_filled),
        "░".repeat(30 - bar_filled),
        ""
    );
    let bar_colour = if pct >= 75 { RED } else if pct >= 40 { YELLOW } else { GREEN };
    println!(" {}Confidence:{} {}{}{}{} {}{}%{}",
        BOLD, RESET,
        bar_colour, BOLD, bar, RESET,
        bar_colour, pct, RESET);
    println!();

    // ── Brand ─────────────────────────────────────────────────────────────────
    if main_brand != VMBrand::Invalid {
        println!(" {}VM Brand:{}    {}{}{}", BOLD, RESET, YELLOW, main_brand.as_str(), RESET);
    }

    // ── Multiple brands ───────────────────────────────────────────────────────
    if brands.len() > 1 {
        let brand_list: Vec<&str> = brands.iter().map(|b| b.as_str()).collect();
        println!(" {}All brands:{}  {}", BOLD, RESET, brand_list.join(", "));
    }

    // ── Triggered techniques ──────────────────────────────────────────────────
    println!(" {}Techniques:{} {} triggered", BOLD, RESET, count);

    // ── Hyper-X ───────────────────────────────────────────────────────────────
    let hx_str = match hx {
        HyperXState::Unknown       => format!("{}Unknown{}", GREY, RESET),
        HyperXState::RealVM        => format!("{}Real VM{}", RED, RESET),
        HyperXState::ArtifactVM    => format!("{}Artifact / Nested VM{}", YELLOW, RESET),
        HyperXState::Enlightenment => format!("{}Enlightened host (Hyper-V root partition){}", CYAN, RESET),
    };
    println!(" {}Hyper-X:{}    {}", BOLD, RESET, hx_str);

    // ── Conclusion ────────────────────────────────────────────────────────────
    println!();
    println!("{}{}{}", GREY, "─".repeat(48), RESET);
    println!(" {}", conclusion(None));
    println!();
}

