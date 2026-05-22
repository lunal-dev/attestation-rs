//! Load tester for the attestation service.
//!
//! Usage:
//!   cargo run --release --bin loadtest -- [OPTIONS]
//!
//! Options:
//!   --url <BASE_URL>       Service base URL (default: http://127.0.0.1:8400)
//!   --rps <N>              Target requests per second (default: 50)
//!   --duration <SECS>      Test duration in seconds (default: 10)
//!   --endpoint <ENDPOINT>  "verify", "attest", or "both" (default: verify)
//!   --concurrency <N>      Max concurrent requests (default: rps * 2)

use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Semaphore};
use tokio::time;

#[derive(Clone)]
struct Stats {
    ok: Arc<AtomicU64>,
    err: Arc<AtomicU64>,
    latencies_us: Arc<Mutex<Vec<u64>>>,
}

impl Stats {
    fn new() -> Self {
        Self {
            ok: Arc::new(AtomicU64::new(0)),
            err: Arc::new(AtomicU64::new(0)),
            latencies_us: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn record(&self, ok: bool, latency: Duration) {
        if ok {
            self.ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.err.fetch_add(1, Ordering::Relaxed);
        }
        self.latencies_us
            .lock()
            .await
            .push(latency.as_micros() as u64);
    }

    async fn report(&self, label: &str, elapsed: Duration) {
        let ok = self.ok.load(Ordering::Relaxed);
        let err = self.err.load(Ordering::Relaxed);
        let total = ok + err;
        let rps = total as f64 / elapsed.as_secs_f64();

        let mut lats = self.latencies_us.lock().await;
        lats.sort_unstable();

        let p = |pct: f64| -> f64 {
            if lats.is_empty() {
                return 0.0;
            }
            let idx = ((pct / 100.0) * lats.len() as f64) as usize;
            let idx = idx.min(lats.len() - 1);
            lats[idx] as f64 / 1000.0
        };

        let avg = if lats.is_empty() {
            0.0
        } else {
            lats.iter().sum::<u64>() as f64 / lats.len() as f64 / 1000.0
        };

        println!("\n=== {label} Results ===");
        println!(
            "  Total:    {total} requests in {:.1}s",
            elapsed.as_secs_f64()
        );
        println!("  OK:       {ok}  Errors: {err}");
        println!("  RPS:      {rps:.1} req/s");
        println!("  Latency:");
        println!("    avg:    {avg:.1} ms");
        println!("    p50:    {:.1} ms", p(50.0));
        println!("    p90:    {:.1} ms", p(90.0));
        println!("    p95:    {:.1} ms", p(95.0));
        println!("    p99:    {:.1} ms", p(99.0));
        println!("    max:    {:.1} ms", p(100.0));
    }
}

async fn get_evidence(client: &Client, base_url: &str) -> Result<String, String> {
    let resp = client
        .post(format!("{base_url}/attest"))
        .json(&json!({"platform": "auto"}))
        .send()
        .await
        .map_err(|e| format!("attest request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("attest returned {status}: {body}"));
    }

    let json: Value = resp
        .json()
        .await
        .map_err(|e| format!("parse attest response: {e}"))?;

    let platform = &json["platform"];
    let evidence = &json["evidence"];
    let verify_body = json!({
        "platform": platform,
        "evidence": evidence,
        "params": { "allow_debug": true }
    });

    serde_json::to_string(&verify_body).map_err(|e| format!("serialize: {e}"))
}

async fn run_verify_load(
    client: &Client,
    base_url: &str,
    body: &str,
    rps: u64,
    duration_secs: u64,
    concurrency: u64,
) -> Stats {
    let stats = Stats::new();
    let sem = Arc::new(Semaphore::new(concurrency as usize));
    let interval = Duration::from_secs_f64(1.0 / rps as f64);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_secs);
    let url = format!("{base_url}/verify");

    println!("  Firing at {rps} req/s for {duration_secs}s (concurrency cap: {concurrency})");

    let mut ticker = time::interval(interval);
    let mut spawned = 0u64;

    loop {
        ticker.tick().await;
        if Instant::now() >= deadline {
            break;
        }

        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = url.clone();
        let body = body.to_string();
        let stats = stats.clone();
        spawned += 1;

        tokio::spawn(async move {
            let t0 = Instant::now();
            let result = client
                .post(&url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await;

            let latency = t0.elapsed();
            let ok = match result {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            };
            stats.record(ok, latency).await;
            drop(permit);
        });
    }

    // Wait for in-flight requests
    let _ = sem.acquire_many(concurrency as u32).await;

    println!("  Spawned {spawned} requests");
    stats
}

async fn run_attest_load(
    client: &Client,
    base_url: &str,
    rps: u64,
    duration_secs: u64,
    concurrency: u64,
) -> Stats {
    let stats = Stats::new();
    // TPM is serial, so cap concurrency low
    let effective_concurrency = concurrency.min(4);
    let sem = Arc::new(Semaphore::new(effective_concurrency as usize));
    let interval = Duration::from_secs_f64(1.0 / rps as f64);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_secs);
    let url = format!("{base_url}/attest");

    println!(
        "  Firing at {rps} req/s for {duration_secs}s (concurrency cap: {effective_concurrency}, TPM-limited)"
    );

    let mut ticker = time::interval(interval);
    let mut spawned = 0u64;

    loop {
        ticker.tick().await;
        if Instant::now() >= deadline {
            break;
        }

        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = url.clone();
        let stats = stats.clone();
        spawned += 1;

        tokio::spawn(async move {
            let t0 = Instant::now();
            let result = client
                .post(&url)
                .json(&json!({"platform": "auto"}))
                .send()
                .await;

            let latency = t0.elapsed();
            let ok = match result {
                Ok(resp) => resp.status().is_success(),
                Err(_) => false,
            };
            stats.record(ok, latency).await;
            drop(permit);
        });
    }

    let _ = sem.acquire_many(effective_concurrency as u32).await;

    println!("  Spawned {spawned} requests");
    stats
}

fn parse_arg(args: &[String], flag: &str, default: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| default.to_string())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let base_url = parse_arg(&args, "--url", "http://127.0.0.1:8400");
    let rps: u64 = parse_arg(&args, "--rps", "50")
        .parse()
        .expect("invalid --rps");
    let duration: u64 = parse_arg(&args, "--duration", "10")
        .parse()
        .expect("invalid --duration");
    let endpoint = parse_arg(&args, "--endpoint", "verify");
    let concurrency: u64 = parse_arg(&args, "--concurrency", &(rps * 2).to_string())
        .parse()
        .expect("invalid --concurrency");

    println!("Attestation Service Load Test");
    println!("  URL:         {base_url}");
    println!("  Endpoint:    {endpoint}");
    println!("  Target RPS:  {rps}");
    println!("  Duration:    {duration}s");
    println!("  Concurrency: {concurrency}");

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(concurrency as usize)
        .build()
        .expect("failed to build HTTP client");

    // Health check
    let health = client
        .get(format!("{base_url}/health"))
        .send()
        .await
        .expect("service not reachable — is it running?");
    assert!(
        health.status().is_success(),
        "health check failed: {}",
        health.status()
    );
    println!("  Health:      OK\n");

    if endpoint == "verify" || endpoint == "both" {
        println!("[1/2] Generating attestation evidence for verify payload...");
        let body = get_evidence(&client, &base_url)
            .await
            .expect("failed to get evidence");
        println!("  Evidence size: {} bytes", body.len());

        // Warmup: single request to prime caches
        println!("  Warming up (1 request)...");
        let _ = client
            .post(format!("{base_url}/verify"))
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await;

        println!("\n[2/2] Running VERIFY load test...");
        let start = Instant::now();
        let stats = run_verify_load(&client, &base_url, &body, rps, duration, concurrency).await;
        stats.report("VERIFY", start.elapsed()).await;
    }

    if endpoint == "attest" || endpoint == "both" {
        println!("\nRunning ATTEST load test...");
        let attest_rps = rps.min(20); // TPM can't handle high RPS
        println!("  (Capping attest RPS to {attest_rps} — TPM is a serial device)");
        let start = Instant::now();
        let stats = run_attest_load(&client, &base_url, attest_rps, duration, concurrency).await;
        stats.report("ATTEST", start.elapsed()).await;
    }

    // Final cache status
    println!("\n--- Cache Status ---");
    if let Ok(resp) = client.get(format!("{base_url}/health")).send().await {
        if let Ok(json) = resp.json::<Value>().await {
            println!(
                "  {}",
                serde_json::to_string_pretty(&json["cache"]).unwrap_or_default()
            );
        }
    }
}
