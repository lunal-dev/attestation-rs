use criterion::{black_box, criterion_group, criterion_main, Criterion};
use der::Decode;

use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::claims::extract_claims as snp_extract_claims;
use attestation::platforms::snp::verify::SnpReport;
use attestation::platforms::tdx::claims::extract_claims as tdx_extract_claims;
use attestation::platforms::tdx::verify::parse_tdx_quote;
use attestation::types::ProcessorGeneration;

// Pre-load all test data at compile time so benchmarks do zero I/O.
static SNP_REPORT_BYTES: &[u8] = include_bytes!("../test_data/snp/test-report.bin");
static TDX_QUOTE_V4: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");
static TDX_QUOTE_V5: &[u8] = include_bytes!("../test_data/tdx_quote_5.dat");

// ---------------------------------------------------------------------------
// SNP benchmarks
// ---------------------------------------------------------------------------

fn bench_snp_report_parsing(c: &mut Criterion) {
    c.bench_function("snp_report_parse", |b| {
        b.iter(|| {
            let report = SnpReport::from_bytes(black_box(SNP_REPORT_BYTES)).unwrap();
            black_box(&report);
        });
    });
}

fn bench_snp_claim_extraction(c: &mut Criterion) {
    // Parse once up-front; the benchmark measures only claim extraction.
    let report = SnpReport::from_bytes(SNP_REPORT_BYTES).unwrap();

    c.bench_function("snp_claim_extraction", |b| {
        b.iter(|| {
            let claims = snp_extract_claims(black_box(&report));
            black_box(&claims);
        });
    });
}

fn bench_snp_cert_chain_parsing(c: &mut Criterion) {
    c.bench_function("snp_cert_chain_parse_bundled", |b| {
        b.iter(|| {
            // Exercise the lookup + x509 DER parse of both certs.
            let (ark_der, ask_der) = get_bundled_certs(black_box(ProcessorGeneration::Milan));
            let ark = x509_cert::Certificate::from_der(ark_der).unwrap();
            let ask = x509_cert::Certificate::from_der(ask_der).unwrap();
            black_box((&ark, &ask));
        });
    });
}

// ---------------------------------------------------------------------------
// TDX benchmarks
// ---------------------------------------------------------------------------

fn bench_tdx_v4_quote_parsing(c: &mut Criterion) {
    c.bench_function("tdx_v4_quote_parse", |b| {
        b.iter(|| {
            let quote = parse_tdx_quote(black_box(TDX_QUOTE_V4)).unwrap();
            black_box(&quote);
        });
    });
}

fn bench_tdx_v5_quote_parsing(c: &mut Criterion) {
    c.bench_function("tdx_v5_quote_parse", |b| {
        b.iter(|| {
            let quote = parse_tdx_quote(black_box(TDX_QUOTE_V5)).unwrap();
            black_box(&quote);
        });
    });
}

fn bench_tdx_claim_extraction(c: &mut Criterion) {
    // Parse a v4 quote once; benchmark only claim extraction.
    let quote = parse_tdx_quote(TDX_QUOTE_V4).unwrap();

    c.bench_function("tdx_claim_extraction", |b| {
        b.iter(|| {
            let claims = tdx_extract_claims(black_box(&quote));
            black_box(&claims);
        });
    });
}

// ---------------------------------------------------------------------------
// Criterion wiring
// ---------------------------------------------------------------------------

criterion_group!(
    snp_benches,
    bench_snp_report_parsing,
    bench_snp_claim_extraction,
    bench_snp_cert_chain_parsing,
);

criterion_group!(
    tdx_benches,
    bench_tdx_v4_quote_parsing,
    bench_tdx_v5_quote_parsing,
    bench_tdx_claim_extraction,
);

criterion_main!(snp_benches, tdx_benches);
