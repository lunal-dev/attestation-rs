use criterion::{black_box, criterion_group, criterion_main, Criterion};

use attestation::collateral::DefaultCertProvider;
use attestation::types::VerifyParams;

fn bench_generate_evidence_with_data(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let custom_data = b"benchmark-custom-report-data";

    c.bench_function("az_snp_attest/generate_with_data", |b| {
        b.to_async(&rt).iter(|| async {
            let evidence =
                attestation::platforms::az_snp::attest::generate_evidence(black_box(custom_data))
                    .await
                    .unwrap();
            black_box(&evidence);
        });
    });
}

fn bench_generate_evidence_empty(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("az_snp_attest/generate_empty", |b| {
        b.to_async(&rt).iter(|| async {
            let evidence =
                attestation::platforms::az_snp::attest::generate_evidence(black_box(b""))
                    .await
                    .unwrap();
            black_box(&evidence);
        });
    });
}

fn bench_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let custom_data = b"benchmark-roundtrip-data";
    let params = VerifyParams::default();
    let provider = DefaultCertProvider::new();

    c.bench_function("az_snp_attest/roundtrip", |b| {
        b.to_async(&rt).iter(|| async {
            let evidence = attestation::platforms::az_snp::attest::generate_evidence(
                black_box(custom_data),
            )
            .await
            .unwrap();
            let result = attestation::platforms::az_snp::verify::verify_evidence(
                black_box(&evidence),
                black_box(&params),
                black_box(&provider),
            )
            .await
            .unwrap();
            black_box(&result);
        });
    });
}

criterion_group!(
    benches,
    bench_generate_evidence_with_data,
    bench_generate_evidence_empty,
    bench_roundtrip,
);
criterion_main!(benches);
