use criterion::{black_box, criterion_group, criterion_main, Criterion};

use attestation::types::VerifyParams;

static AZ_TDX_HCL_REPORT: &[u8] = include_bytes!("../test_data/az_tdx/hcl-report.bin");
static AZ_TDX_EVIDENCE_JSON: &str = include_str!("../test_data/az_tdx/evidence-v1.json");

fn bench_hcl_report_parse(c: &mut Criterion) {
    c.bench_function("az_tdx/hcl_report_parse", |b| {
        b.iter(|| {
            let parsed =
                attestation::platforms::tpm_common::parse_hcl_report(black_box(AZ_TDX_HCL_REPORT))
                    .unwrap();
            black_box(&parsed);
        });
    });
}

fn bench_evidence_deserialize(c: &mut Criterion) {
    c.bench_function("az_tdx/evidence_deserialize", |b| {
        b.iter(|| {
            let e: attestation::platforms::az_tdx::evidence::AzTdxEvidence =
                serde_json::from_str(black_box(AZ_TDX_EVIDENCE_JSON)).unwrap();
            black_box(&e);
        });
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    let evidence: attestation::platforms::az_tdx::evidence::AzTdxEvidence =
        serde_json::from_str(AZ_TDX_EVIDENCE_JSON).unwrap();
    let params = VerifyParams::default();
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("az_tdx/full_pipeline", |b| {
        b.to_async(&rt).iter(|| async {
            let result = attestation::platforms::az_tdx::verify::verify_evidence(
                black_box(&evidence),
                black_box(&params),
            )
            .await
            .unwrap();
            black_box(&result);
        });
    });
}

criterion_group!(
    benches,
    bench_hcl_report_parse,
    bench_evidence_deserialize,
    bench_full_pipeline,
);
criterion_main!(benches);
