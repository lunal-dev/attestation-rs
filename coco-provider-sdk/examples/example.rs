use coco_provider::coco::ReportRequest;
use coco_provider::get_coco_provider;
fn main() {
    let provider = get_coco_provider().unwrap();
    println!("Provider: {:?}", provider);

    let request = ReportRequest {
        report_data: None,
        vmpl: None,
    };

    let report = provider.device.get_report(&request).unwrap();
    println!("Report: {:?}", report.report);
}
