use crate::types::{Claims, TcbInfo};

use super::verify::SnpReport;

/// Extract normalized claims from a parsed SNP attestation report.
pub fn extract_claims(report: &SnpReport) -> Claims {
    let platform_data = serde_json::json!({
        "policy": {
            "abi_major": report.policy_abi_major,
            "abi_minor": report.policy_abi_minor,
            "smt_allowed": report.policy_smt_allowed,
            "migrate_ma": report.policy_migrate_ma,
            "debug_allowed": report.policy_debug_allowed,
            "single_socket": report.policy_single_socket,
        },
        "platform_info": {
            "tsme_enabled": report.plat_tsme_enabled,
            "smt_enabled": report.plat_smt_enabled,
        },
        "vmpl": report.vmpl,
        "chip_id": hex::encode(&report.chip_id),
        "current_build": report.current_build,
        "current_minor": report.current_minor,
        "current_major": report.current_major,
        "committed_build": report.committed_build,
        "committed_minor": report.committed_minor,
        "committed_major": report.committed_major,
        "guest_svn": report.guest_svn,
        "signature_algo": report.signature_algo,
    });

    Claims {
        launch_digest: hex::encode(&report.measurement),
        report_data: report.report_data.to_vec(),
        init_data: report.host_data.to_vec(),
        tcb: TcbInfo::Snp {
            bootloader: report.reported_tcb_bootloader,
            tee: report.reported_tcb_tee,
            snp: report.reported_tcb_snp,
            microcode: report.reported_tcb_microcode,
        },
        platform_data,
    }
}
