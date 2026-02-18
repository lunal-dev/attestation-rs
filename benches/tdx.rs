use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use attestation::platforms::tdx::claims::extract_claims;
use attestation::platforms::tdx::verify::parse_tdx_quote;

static TDX_QUOTE_V4: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");
static TDX_QUOTE_V5: &[u8] = include_bytes!("../test_data/tdx_quote_5.dat");

fn bench_v4_quote_parse(c: &mut Criterion) {
    c.bench_function("tdx/v4_quote_parse", |b| {
        b.iter(|| {
            let quote = parse_tdx_quote(black_box(TDX_QUOTE_V4)).unwrap();
            black_box(&quote);
        });
    });
}

fn bench_v5_quote_parse(c: &mut Criterion) {
    c.bench_function("tdx/v5_quote_parse", |b| {
        b.iter(|| {
            let quote = parse_tdx_quote(black_box(TDX_QUOTE_V5)).unwrap();
            black_box(&quote);
        });
    });
}

fn bench_claim_extraction(c: &mut Criterion) {
    let quote = parse_tdx_quote(TDX_QUOTE_V4).unwrap();
    c.bench_function("tdx/claim_extraction", |b| {
        b.iter(|| {
            let claims = extract_claims(black_box(&quote));
            black_box(&claims);
        });
    });
}

fn bench_evidence_deserialize(c: &mut Criterion) {
    let evidence = attestation::platforms::tdx::evidence::TdxEvidence {
        quote: base64::engine::general_purpose::STANDARD.encode(TDX_QUOTE_V4),
        cc_eventlog: None,
    };
    let json = serde_json::to_string(&evidence).unwrap();

    c.bench_function("tdx/evidence_deserialize", |b| {
        b.iter(|| {
            let e: attestation::platforms::tdx::evidence::TdxEvidence =
                serde_json::from_str(black_box(&json)).unwrap();
            black_box(&e);
        });
    });
}

criterion_group!(
    benches,
    bench_v4_quote_parse,
    bench_v5_quote_parse,
    bench_claim_extraction,
    bench_evidence_deserialize,
);
criterion_main!(benches);
