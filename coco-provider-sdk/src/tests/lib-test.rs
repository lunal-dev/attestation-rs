use crate::get_coco_provider;
use crate::utils::get_current_uid;

/// This test should always fail if test is not running as root, as device requires root privileges.
/// If test is running as root, it should pass if the machine this test is run on has a CoCo device.
#[test]
fn test_get_coco_provider() {
    let provider = get_coco_provider();
    if get_current_uid() != 0 {
        assert!(!provider.is_ok());
    } else {
        assert!(provider.is_ok());
    }
}
