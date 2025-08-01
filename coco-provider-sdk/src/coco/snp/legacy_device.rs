use super::snp_error::*;
use super::types::{CertTableEntry, CertTableEntryRaw, DerivedKey};
use crate::error::*;
use iocuddle::{Group, Ioctl, WriteRead};
use std::fs::{File, OpenOptions};
use std::marker::PhantomData;

const MAX_VMPL: u32 = 3;
const REPORT_SIZE: usize = 1184;

/// Checks the `fw_err` field on the [GuestRequest](crate::firmware::linux::guest::ioctl::GuestRequest) structure
/// to make sure that no errors were encountered by the VMM or the AMD Secure Processor.
fn map_fw_err(raw_error: RawFwError) -> CocoError {
    let (upper, lower): (u32, u32) = raw_error.into();

    if upper != 0 {
        return VmmError::from(upper).into();
    }

    if lower != 0 {
        return FirmwareError::from(lower).into();
    }

    FirmwareError::UnknownSevError(lower).into()
}

/// A handle to the SEV-SNP guest device.
pub struct Firmware(File);

impl Firmware {
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).open("/dev/sev-guest")?,
        ))
    }

    /// Requests an attestation report from the AMD Secure Processor. The `message_version` will default
    /// to `1` if `None` is specified.
    pub fn get_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<[u8; REPORT_SIZE]> {
        let mut input = ReportReq::new(data, vmpl)?;
        let mut response = ReportRsp::default();

        let mut request: GuestRequest<ReportReq, ReportRsp> =
            GuestRequest::new(message_version, &mut input, &mut response);

        SNP_GET_REPORT
            .ioctl(&mut self.0, &mut request)
            .map_err(|_| map_fw_err(request.fw_err.into()))?;

        // Make sure response status is successful
        if response.status != 0 {
            return Err(CocoError::Firmware(format!(
                "SEV error code: {}",
                response.status
            )));
        }

        Ok(response.report)
    }

    /// Request an extended attestation report from the AMD Secure Processor.
    /// The `message_version` will default to `1` if `None` is specified.
    ///
    /// Behaves the same as [get_report](crate::firmware::guest::Firmware::get_report).
    pub fn get_ext_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<([u8; REPORT_SIZE], Option<Vec<CertTableEntry>>)> {
        let report_request = ReportReq::new(data, vmpl)?;

        let mut report_response = ReportRsp::default();

        // Define a buffer to store the certificates in.
        let mut certificate_bytes: Vec<u8>;

        // Due to the complex buffer allocation, we will take the ReportReq
        // provided by the caller, and create an extended report request object
        // for them.
        let mut ext_report_request = ExtReportReq::new(&report_request);

        // Construct the object needed to perform the IOCTL request.
        // *NOTE:* This is __important__ because a fw_err value which matches
        // [InvalidCertificatePageLength](crate::error::VmmError::InvalidCertificatePageLength) will indicate the buffer was not large
        // enough.
        let mut guest_request: GuestRequest<ExtReportReq, ReportRsp> = GuestRequest::new(
            message_version,
            &mut ext_report_request,
            &mut report_response,
        );

        // KEEP for Kernels before 47894e0f (5.19), as userspace broke at that hash.
        if SNP_GET_EXT_REPORT
            .ioctl(&mut self.0, &mut guest_request)
            .is_err()
        {
            match guest_request.fw_err.into() {
                // The kernel patch by pgonda@google.com in kernel hash 47894e0f
                // changed the ioctl return to succeed instead of returning an
                // error when encountering an invalid certificate length. This was
                // done to keep the cryptography safe, so we will now just check
                // the guest_request.fw_err for a new value.
                //
                // Check to see if the buffer needs to be resized. If it does, the
                // we need to resize the buffer to the correct size, and
                // re-request for the certificates.
                VmmError::InvalidCertificatePageLength => {
                    certificate_bytes = vec![0u8; ext_report_request.certs_len as usize];
                    ext_report_request.certs_address = certificate_bytes.as_mut_ptr() as u64;
                    let mut guest_request_retry: GuestRequest<ExtReportReq, ReportRsp> =
                        GuestRequest::new(
                            message_version,
                            &mut ext_report_request,
                            &mut report_response,
                        );
                    SNP_GET_EXT_REPORT
                        .ioctl(&mut self.0, &mut guest_request_retry)
                        .map_err(|_| map_fw_err(guest_request_retry.fw_err.into()))?;
                }
                _ => Err(map_fw_err(guest_request.fw_err.into()))?,
            }
        }

        // Make sure response status is successful
        if report_response.status != 0 {
            return Err(CocoError::Firmware(format!(
                "SEV error code: {}",
                report_response.status
            )));
        }

        if ext_report_request.certs_len == 0 {
            return Ok((report_response.report, None));
        }

        let mut certificates: Vec<CertTableEntry>;

        unsafe {
            let entries = (ext_report_request.certs_address as *mut CertTableEntryRaw)
                .as_mut()
                .ok_or(CocoError::Firmware(
                    "Empty cert buffer from device".to_string(),
                ))?;
            certificates = CertTableEntryRaw::parse_table(entries)?;
            certificates.sort();
        }

        // Return both the Attestation Report, as well as the Cert Table.
        Ok((report_response.report, Some(certificates)))
    }

    /// Fetches a derived key from the AMD Secure Processor. The `message_version` will default to `1` if `None` is specified.
    ///
    /// # Example:
    /// ```ignore
    /// let request: DerivedKey = DerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0);
    ///
    /// let mut fw: Firmware = Firmware::open().unwrap();
    /// let derived_key: DerivedKeyRsp = fw.get_derived_key(None, request).unwrap();
    /// ```
    pub fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        derived_key_request: DerivedKey,
    ) -> Result<[u8; 32]> {
        let mut ffi_derived_key_request: DerivedKeyReq = derived_key_request.into();
        let mut ffi_derived_key_response: DerivedKeyRsp = Default::default();

        {
            let mut request: GuestRequest<DerivedKeyReq, DerivedKeyRsp> = GuestRequest::new(
                message_version,
                &mut ffi_derived_key_request,
                &mut ffi_derived_key_response,
            );

            SNP_GET_DERIVED_KEY
                .ioctl(&mut self.0, &mut request)
                .map_err(|_| map_fw_err(request.fw_err.into()))?;
        }

        // Make sure response status is successfuls
        if ffi_derived_key_response.status != 0 {
            return Err(CocoError::Firmware(format!(
                "SEV Error code: {}",
                ffi_derived_key_response.status
            )));
        }

        Ok(ffi_derived_key_response.key)
    }
}

pub enum GuestIoctl {
    GetReport = 0x0,
    GetDerivedKey = 0x1,
    GetExtReport = 0x2,
    _Undefined,
}

const SEV: Group = Group::new(b'S');

pub const SNP_GET_REPORT: Ioctl<WriteRead, &GuestRequest<ReportReq, ReportRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetReport as u8) };

pub const SNP_GET_DERIVED_KEY: Ioctl<WriteRead, &GuestRequest<DerivedKeyReq, DerivedKeyRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetDerivedKey as u8) };

pub const SNP_GET_EXT_REPORT: Ioctl<WriteRead, &GuestRequest<ExtReportReq, ReportRsp>> =
    unsafe { SEV.write_read(GuestIoctl::GetExtReport as u8) };

/// The default structure used for making requests to the PSP as a guest owner.
#[repr(C)]
pub struct GuestRequest<'a, 'b, Req, Rsp> {
    /// Message version number (must be non-zero)
    pub message_version: u32,
    /// Request structure address.
    pub request_data: u64,
    /// Response structure address.
    pub response_data: u64,
    /// Firmware error address.
    pub fw_err: u64,

    _phantom_req: PhantomData<&'a mut Req>,
    _phantom_rsp: PhantomData<&'b mut Rsp>,
}

impl<'a, 'b, Req, Rsp> GuestRequest<'a, 'b, Req, Rsp> {
    /// Creates a new request from the addresses provided.
    ///
    /// # Arguments:
    ///
    /// * `ver` - Option<u32> - Version of the message.
    /// * `req` - &Req - The reference a Request object.
    /// * `rsp` - &Rsp - The reference a Response object.
    pub fn new(ver: Option<u32>, req: &'a mut Req, rsp: &'b mut Rsp) -> Self {
        Self {
            message_version: ver.unwrap_or(1),
            request_data: req as *mut Req as u64,
            response_data: rsp as *mut Rsp as u64,
            fw_err: Default::default(),
            _phantom_req: PhantomData,
            _phantom_rsp: PhantomData,
        }
    }
}

/// Information provided by the guest owner for requesting an attestation
/// report and associated certificate chain from the AMD Secure Processor.
///
/// The certificate buffer *should* be page aligned for the kernel.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExtReportReq {
    /// The [ReportReq](self::ReportReq).
    pub data: ReportReq,

    /// Starting address of the certificate data buffer.
    pub certs_address: u64,

    /// The page aligned length of the buffer the hypervisor should store the certificates in.
    pub certs_len: u32,
}

impl ExtReportReq {
    /// Creates a new exteded report with a one, 4K-page
    /// for the certs_address field and the certs_len field.
    pub fn new(data: &ReportReq) -> Self {
        Self {
            data: *data,
            certs_address: u64::MAX,
            certs_len: 0u32,
        }
    }
}

/// Information provided by the guest owner for requesting an attestation
/// report from the AMD Secure Processor.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct ReportReq {
    /// Guest-provided data to be included int the attestation report
    report_data: [u8; 64],

    /// The VMPL to put into the attestation report. Must be greater than or
    /// equal to the current VMPL and at most three.
    vmpl: u32,

    /// Reserved memory slot, must be zero.
    _reserved: [u8; 28],
}

impl Default for ReportReq {
    fn default() -> Self {
        Self {
            report_data: [0; 64],
            vmpl: 1,
            _reserved: Default::default(),
        }
    }
}

impl ReportReq {
    /// Instantiates a new [ReportReq](self::ReportReq) for fetching an [AttestationReport](crate::firmware::guest::types::snp::AttestationReport) from the PSP.
    ///
    /// # Arguments
    ///
    /// * `report_data` - (Optional) 64 bytes of unique data to be included in the generated report.
    /// * `vmpl` - The VMPL level the guest VM is running on.
    pub fn new(report_data: Option<[u8; 64]>, vmpl: Option<u32>) -> Result<Self> {
        let mut request = Self::default();

        if let Some(report_data) = report_data {
            request.report_data = report_data;
        }

        if let Some(vmpl) = vmpl {
            if vmpl > MAX_VMPL {
                return Err(CocoError::Firmware("VmplError".to_string()));
            } else {
                request.vmpl = vmpl;
            }
        }

        Ok(request)
    }
}

/// The response from the PSP containing the generated attestation report.
///
/// The Report is padded to exactly 4000 Bytes to make sure the page size
/// matches.
///
///
/// ```txt
///     96 Bytes (*Message Header)
/// + 4000 Bytes (*Encrypted Message)
/// ------------
///   4096 Bytes (4K Memory Page Alignment)
/// ```
/// <sup>*[Message Header - 8.26 SNP_GUEST_REQUEST - Table 100, May 2025 rev 1.58](<https://www.amd.com/system/files/TechDocs/56860.pdf#page=125>)</sup>
///
/// <sup>*[Encrypted Message - sev-guest.h](<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/sev-guest.h>)</sup>
///
/// <sup>*[Message Structure - 7.3 MSG_REPORT_RSP - Table 25, May 2025 rev 1.58](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf#page=62)</sup>
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ReportRsp {
    /// The status of key derivation operation.
    ///     0h: Success.
    ///     16h: Invalid parameters.
    ///     27h: Invalid key selection.
    pub status: u32,
    /// Size in bytes of the report.
    pub report_size: u32,
    reserved_0: [u8; 24],
    /// The attestation report generated by the firmware.
    pub report: [u8; REPORT_SIZE],
    /// Padding bits to meet the memory page alignment.
    reserved_1: [u8; 4000
        - (REPORT_SIZE + (std::mem::size_of::<u32>() * 2) + std::mem::size_of::<[u8; 24]>())],
}

impl Default for ReportRsp {
    fn default() -> Self {
        Self {
            status: Default::default(),
            report_size: Default::default(),
            reserved_0: Default::default(),
            report: [0u8; REPORT_SIZE],
            reserved_1: [0u8; 4000
                - (REPORT_SIZE
                    + (std::mem::size_of::<u32>() * 2)
                    + std::mem::size_of::<[u8; 24]>())],
        }
    }
}

#[repr(C)]
pub struct DerivedKeyReq {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,

    /// Reserved, must be zero
    reserved_0: u32,

    /// What data will be mixed into the derived key.
    pub guest_field_select: u64,

    /// The VMPL to mix into the derived key. Must be greater than or equal
    /// to the current VMPL.
    pub vmpl: u32,

    /// The guest SVN to mix into the key. Must not exceed the guest SVN
    /// provided at launch in the ID block.
    pub guest_svn: u32,

    /// The TCB version to mix into the derived key. Must not
    /// exceed CommittedTcb.
    pub tcb_version: u64,
}

impl From<DerivedKey> for DerivedKeyReq {
    fn from(value: DerivedKey) -> Self {
        Self {
            root_key_select: value.get_root_key_select(),
            reserved_0: Default::default(),
            guest_field_select: value.guest_field_select.0,
            vmpl: value.vmpl,
            guest_svn: value.guest_svn,
            tcb_version: value.tcb_version,
        }
    }
}

impl From<&mut DerivedKey> for DerivedKeyReq {
    fn from(value: &mut DerivedKey) -> Self {
        Self {
            root_key_select: value.get_root_key_select(),
            reserved_0: Default::default(),
            guest_field_select: value.guest_field_select.0,
            vmpl: value.vmpl,
            guest_svn: value.guest_svn,
            tcb_version: value.tcb_version,
        }
    }
}

#[derive(Default, Debug)]
#[repr(C)]
/// A raw representation of the PSP Report Response after calling SNP_GET_DERIVED_KEY.
pub struct DerivedKeyRsp {
    /// The status of key derivation operation.
    /// 0h: Success.
    /// 16h: Invalid parameters
    pub status: u32,

    reserved_0: [u8; 28],

    /// The requested derived key if [DerivedKeyRsp::status](self::DerivedKeyRsp::status) is 0h.
    pub key: [u8; 32],
}
