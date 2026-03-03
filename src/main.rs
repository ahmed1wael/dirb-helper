use clap::Parser;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command};
use std::thread;
use std::time::Duration;
use chrono::Local;
use serde::Serialize;
use regex::Regex;

#[derive(Serialize, Debug, Clone)]
struct ScanResult {
    path: String,
    full_url: String,
    status_code: u16,
    size: u32,
    priority: String,
    risk_level: String,
    raw_line: String,
}

#[derive(Serialize, Debug)]
struct ScanReport {
    meta: MetaData,
    summary: Summary,
    results: Vec<ScanResult>,
}

#[derive(Serialize, Debug)]
struct MetaData {
    tool: String,
    version: String,
    timestamp: String,
    target: String,
}

#[derive(Serialize, Debug)]
struct Summary {
    total_paths: usize,
    critical: usize,
    interesting: usize,
    noise: usize,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {

    #[arg(short, long)]
    command: Option<String>,

    #[arg(short, long)]
    file: Option<PathBuf>,

    #[arg(short, long)]
    output_path: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();

    let base_output = match args.output_path {
        Some(path) => path.join("dirb-helper-output"),
        None => PathBuf::from("output"),
    };

    if let Err(e) = fs::create_dir_all(&base_output) {
        eprintln!("Failed to create output directory: {}", e);
        return;
    }

    // 4. تنفيذ المسح
    if let Some(cmd_str) = args.command {
        println!("🚀 Starting scan with command: {}", cmd_str);
        run_single_scan(&cmd_str, &base_output);
    } else if let Some(file_path) = args.file {
        println!("📂 Running batch mode from file: {:?}", file_path);
        run_batch_scan(&file_path, &base_output);
    } else {
        println!("❌ No command or file provided. Use -h for help.");
    }
}

fn run_single_scan(cmd_str: &str, output_dir: &Path) {

    let output = Command::new("bash")
        .arg("-c")
        .arg(cmd_str)
        .output()
        .expect("Failed to execute dirb command");

    let raw_output = String::from_utf8_lossy(&output.stdout);
    
    let timestamp = Local::now().format("%Y-%m-%d_T%H-%M-%S");
    let raw_filename = format!("normal_output_dirb_file-{}.txt", timestamp);
    let mut raw_file = File::create(output_dir.join(&raw_filename)).unwrap();
    raw_file.write_all(raw_output.as_bytes()).unwrap();

    let report = normalize_and_filter(&raw_output);

    let json_filename = format!("normalized_dirb_output-{}.json", timestamp);
    let json_path = output_dir.join(&json_filename);
    let json_file = File::create(&json_path).unwrap();
    serde_json::to_writer_pretty(json_file, &report).unwrap();

    println!("✅ Scan complete. Files saved in {:?}", output_dir);
    println!("📄 Raw: {}", raw_filename);
    println!("📊 Normalized: {}", json_filename);

    thread::sleep(Duration::from_secs(2));
}

fn run_batch_scan(file_path: &Path, output_dir: &Path) {
    let file = File::open(file_path).expect("Cannot open command file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let cmd = line.unwrap();
        if !cmd.trim().is_empty() && !cmd.trim().starts_with('#') {
            run_single_scan(&cmd, output_dir);
        }
    }
}

fn normalize_and_filter(raw_output: &str) -> ScanReport {
    let mut results: Vec<ScanResult> = Vec::new();
    let mut target_url = String::from("Unknown");

    // 1. استخراج الهدف من مخرجات dirb
    if let Some(url_line) = raw_output.lines().find(|l| l.contains("URL_BASE:")) {
        target_url = url_line.split("URL_BASE:").nth(1).unwrap_or("Unknown").trim().to_string();
    }

    // 2. Regex المصحح ليتطابق مع صيغة dirb الفعلية
    // الصيغة: + https://example.com/path (CODE:200|SIZE:1234)
    let re = Regex::new(r"\+ (https?://[^\s]+) \(CODE:(\d+)\|SIZE:(\d+)\)").unwrap();

    for cap in re.captures_iter(raw_output) {
        let full_url = cap.get(1).map_or("", |m| m.as_str()).to_string();
        let code: u16 = cap.get(2).map_or("0", |m| m.as_str()).parse().unwrap_or(0);
        let size: u32 = cap.get(3).map_or("0", |m| m.as_str()).parse().unwrap_or(0);
        let raw_line = cap.get(0).map_or("", |m| m.as_str()).to_string();

        // استخراج المسار من الرابط الكامل (اختياري)
        let path = full_url.strip_prefix(&target_url).unwrap_or(&full_url).to_string();

        // 3. تحديد الأولوية بشكل أدق
        let (priority, risk_level) = match code {
            200 => ("high", "critical"),
            500 => ("high", "critical"),
            503 => ("medium", "interesting"), // Service Unavailable قد يعني WAF
            403 => ("medium", "interesting"), // Forbidden قد يعني مسار محمي
            401 => ("medium", "interesting"), // Unauthorized
            301 | 302 => ("low", "redirect"),
            429 => ("low", "rate_limited"),    // Too Many Requests
            _ => ("low", "noise"),
        };

        results.push(ScanResult {
            path,
            full_url,
            status_code: code,
            size,
            priority: priority.to_string(),
            risk_level: risk_level.to_string(),
            raw_line,
        });
    }

    // 4. فرز النتائج حسب الأهمية
    results.sort_by(|a, b| {
        let priority_score = |p: &str| match p {
            "high" => 0,
            "medium" => 1,
            _ => 2,
        };
        priority_score(&a.priority).cmp(&priority_score(&b.priority))
    });

    // 5. حساب الإحصائيات
    let critical = results.iter().filter(|r| r.risk_level == "critical").count();
    let interesting = results.iter().filter(|r| r.risk_level == "interesting").count();
    let noise = results.iter().filter(|r| r.risk_level == "noise" || r.risk_level == "redirect").count();

    ScanReport {
        meta: MetaData {
            tool: "dirb-helper".to_string(),
            version: "0.1.0".to_string(),
            timestamp: Local::now().to_rfc3339(),
            target: target_url,
        },
        summary: Summary {
            total_paths: results.len(),
            critical,
            interesting,
            noise,
        },
        results,
    }
}