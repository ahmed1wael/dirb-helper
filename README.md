#dirb-helper

A Rust-based utility to wrap, normalize, and filter `dirb` output for the **Arsenal Security Project**.

##Features
- **Smart Normalization**: Converts raw text output into structured JSON.
- **Priority Filtering**: Sorts results by status code (200/500 first).
- **Batch Mode**: Run multiple scans from a command file.
- **Memory Safe**: Built with Rust for reliability.

##Installation

cargo build --release

##Usage

Single Scan:
./target/release/dirb-helper -c "dirb http://target.com"

Batch Scan:
./target/release/dirb-helper -f commands.txt

Custom Output Path:
./target/release/dirb-helper -c "dirb http://target.com" -o /home/user/scans
