use crate::types::{Claims, TcbInfo};

use super::verify::TdxQuote;

/// Extract normalized claims from a parsed TDX quote.
pub fn extract_claims(quote: &TdxQuote) -> Claims {
    let platform_data = serde_json::json!({
        "quote_version": format!("{:?}", quote.quote_version),
        "tee_type": format!("0x{:x}", quote.header.tee_type),
        "mr_seam": hex::encode(&quote.body.mr_seam),
        "mrsigner_seam": hex::encode(&quote.body.mrsigner_seam),
        "seam_attributes": hex::encode(&quote.body.seam_attributes),
        "td_attributes": hex::encode(&quote.body.td_attributes),
        "xfam": hex::encode(&quote.body.xfam),
        "mr_config_id": hex::encode(&quote.body.mr_config_id),
        "mr_owner": hex::encode(&quote.body.mr_owner),
        "mr_owner_config": hex::encode(&quote.body.mr_owner_config),
        "rtmr_0": hex::encode(&quote.body.rtmr_0),
        "rtmr_1": hex::encode(&quote.body.rtmr_1),
        "rtmr_2": hex::encode(&quote.body.rtmr_2),
        "rtmr_3": hex::encode(&quote.body.rtmr_3),
    });

    Claims {
        launch_digest: hex::encode(&quote.body.mr_td),
        report_data: quote.body.report_data.to_vec(),
        init_data: quote.body.mr_config_id.to_vec(),
        tcb: TcbInfo::Tdx {
            tcb_svn: quote.body.tee_tcb_svn.to_vec(),
        },
        platform_data,
    }
}
