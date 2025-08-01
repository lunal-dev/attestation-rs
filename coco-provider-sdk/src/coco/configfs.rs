use crate::coco::{Device, ReportRequest, ReportResponse, CONFIGFS_BASE_PATH};
use crate::error::{CocoError, Result};
use crate::utils::{generate_random_data, generate_random_number};
use log::error;
use std::any::Any;
use std::fmt;
use std::fs;
use std::fs::{create_dir_all, remove_dir};

#[derive(Debug)]
/// This attribute is used to read/write data to/from the ConfigFS.
pub enum TsmReportAttribute {
    /// Read only. Only for AMD. Holds certs.
    AuxBlob,
    /// Write only. Used for report_data
    InBlob,
    /// Read only. Use this to read the attestation report.
    OutBlob,
    /// Read only. Use this for tamper checking.
    Generation,
    /// Write only. Only for AMD. Used for VMPL. Provide a value between 0-3.
    PrivLevel,
    /// Read only
    PrivLevelFloor,
    /// Read only. Returns a string (eg. tdx_guest, sev_guest)
    Provider,
}

impl fmt::Display for TsmReportAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let output = format!("{:?}", self);
        write!(f, "{}", output.to_lowercase())
    }
}

/// ConfigFs is the unified standard for retrieving attestation reports from different
/// confidential computing hardware providers.
/// Note:
/// For this struct, please make a new instance everytime you wish to generate a new
/// report, as each struct is associated with one folder and hence, it can only be used once.
///
///
/// Additionally, it does the following two things:
/// 1. It wraps over a ConfigFsClient which does the real work.
/// 2. Provides additional checks to ensure the result we get is not tampered with.
#[derive(Clone, Debug)]
pub struct ConfigFs {}

#[derive(Clone, Debug)]
pub struct ConfigFsClient {
    /// Path to the folder where we can retrieve the Quote/Signed Attestation Report.
    /// And also other things that the provider may want to provide
    device_path: String,
    /// Expected generation number - track this for every write to watch out for tampering.
    expected_generation: u32,
}

impl ConfigFs {
    pub fn new() -> Self {
        ConfigFs {}
    }

    fn new_device(&self) -> Result<ConfigFsClient> {
        let rand_num = generate_random_number();
        let device_path = format!("{}/report-{}", CONFIGFS_BASE_PATH, rand_num);
        let client = ConfigFsClient::new(device_path)?;
        Ok(client)
    }

    pub fn get_certificates(&self) -> Result<Vec<u8>> {
        let mut client = self.new_device()?;

        // Wite the report_data/nonce into inblob
        let report_data = generate_random_data();
        client.write_attribute(&TsmReportAttribute::InBlob, &report_data)?;

        // Write the privilege level into the privilege attribute.
        let priv_str = 0.to_string();
        let priv_bytes = priv_str.as_bytes();
        client.write_attribute(&TsmReportAttribute::PrivLevel, priv_bytes)?;

        // Get certs from auxblob
        let certs = client.read_attribute(&TsmReportAttribute::AuxBlob)?;

        Ok(certs)
    }

    /// Returns the provider of the report.
    /// Examples: tdx_guest, sev_guest, etc...
    pub fn get_provider(&self) -> Result<String> {
        let client: ConfigFsClient = self.new_device()?;
        Ok(client.read_attribute_string(&TsmReportAttribute::Provider)?)
    }
}

impl Device for ConfigFs {
    fn get_report(&self, req: &ReportRequest) -> Result<ReportResponse> {
        let mut client = self.new_device()?;
        // Wite the report_data/nonce into inblob
        let report_data = req.report_data.unwrap_or_else(generate_random_data);
        client.write_attribute(&TsmReportAttribute::InBlob, &report_data)?;

        if req.vmpl.is_some_and(|x| x <= 3) {
            // Write the privilege level into the privilege attribute.
            let priv_str = req.vmpl.unwrap().to_string();
            let priv_bytes = priv_str.as_bytes();
            client.write_attribute(&TsmReportAttribute::PrivLevel, priv_bytes)?;
        }

        // Now read the outblob. This is the report.
        let report = client.read_attribute(&TsmReportAttribute::OutBlob)?;

        Ok(ReportResponse {
            report,
            var_data: None,
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ConfigFsClient {
    pub fn new(device_path: String) -> Result<Self> {
        create_dir_all(&device_path)?;
        let expected_generation =
            read_attribute_u32(&device_path, &TsmReportAttribute::Generation)?;

        Ok(ConfigFsClient {
            device_path,
            expected_generation,
        })
    }

    /// Wrapper over client.write_attribute as we want to keep track of self.expected_generation
    pub fn write_attribute(&mut self, attribute: &TsmReportAttribute, data: &[u8]) -> Result<()> {
        _write_attribute(&self.device_path, attribute, data)?;
        self.expected_generation += 1;
        Ok(())
    }

    pub fn read_attribute(&self, attribute: &TsmReportAttribute) -> Result<Vec<u8>> {
        let output = _read_attribute(&self.device_path, attribute)?;
        self.check_tampering()?;
        Ok(output)
    }

    fn check_tampering(&self) -> Result<()> {
        let gen = read_attribute_u32(&self.device_path, &TsmReportAttribute::Generation)?;
        if self.expected_generation != gen {
            return Err(CocoError::Firmware(
                "Generation number mismatch".to_string(),
            ));
        }
        Ok(())
    }

    pub fn read_attribute_string(&self, attribute: &TsmReportAttribute) -> Result<String> {
        let res = _read_attribute(&self.device_path, attribute)?;
        Ok(String::from_utf8(res)?)
    }
}

fn _write_attribute(device_path: &str, attribute: &TsmReportAttribute, data: &[u8]) -> Result<()> {
    let path = format!("{}/{}", device_path, attribute);
    fs::write(path, data)?;
    Ok(())
}

fn _read_attribute(device_path: &str, attribute: &TsmReportAttribute) -> Result<Vec<u8>> {
    let path = format!("{}/{}", device_path, attribute);
    Ok(fs::read(&path)?)
}

fn read_attribute_u32(device_path: &str, attribute: &TsmReportAttribute) -> Result<u32> {
    let res = _read_attribute(device_path, attribute)?;
    let res = String::from_utf8(res)?;
    let res = res.replace("\n", "");
    let num: u32 = res.parse()?;
    Ok(num)
}

impl Drop for ConfigFsClient {
    fn drop(&mut self) {
        // Clean up the report folder when it goes out of scope, as it's meant to be temporary.
        match remove_dir(&self.device_path) {
            Ok(_) => (),
            Err(e) => error!("Error cleaning up {}: {:?}", &self.device_path, e),
        }
    }
}
