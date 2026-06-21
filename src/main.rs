// SPDX-FileCopyrightText: 2026 Nerijus Bendžiūnas
// SPDX-License-Identifier: MIT

mod cli;
mod jsonl_reporter;
mod text_reporter;

use clap::Parser;

use cli::Cli;

fn main() {
    if let Err(e) = Cli::parse().run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
