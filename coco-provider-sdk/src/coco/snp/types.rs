use bitfield::bitfield;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
/// Certificates which are accepted for [CertTableEntry](self::CertTableEntry)
pub enum CertType {
    /// Empty or closing entry for the CertTable
    Empty,

    /// AMD Root Signing Key (ARK) certificate
    ARK,

    /// AMD SEV Signing Key (ASK) certificate
    ASK,

    /// Versioned Chip Endorsement Key (VCEK) certificate
    VCEK,

    /// Versioned Loaded Endorsement Key (VLEK) certificate
    VLEK,

    /// Certificate Revocation List (CRLs) certificate(s)
    CRL,

    /// Other (Specify GUID)
    OTHER(uuid::Uuid),
}

impl std::fmt::Display for CertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guid = match self {
            CertType::Empty => "00000000-0000-0000-0000-000000000000".to_string(),
            CertType::ARK => "c0b406a4-a803-4952-9743-3fb6014cd0ae".to_string(),
            CertType::ASK => "4ab7b379-bbac-4fe4-a02f-05aef327c782".to_string(),
            CertType::VCEK => "63da758d-e664-4564-adc5-f4b93be8accd".to_string(),
            CertType::VLEK => "a8074bc2-a25a-483e-aae6-39c045a0b8a1".to_string(),
            CertType::CRL => "92f81bc3-5811-4d3d-97ff-d19f88dc67ea".to_string(),
            CertType::OTHER(guid) => guid.to_string(),
        };

        write!(f, "{}", guid)
    }
}

impl TryFrom<CertType> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(value: CertType) -> Result<Self, Self::Error> {
        match value {
            CertType::Empty => uuid::Uuid::parse_str(&CertType::Empty.to_string()),
            CertType::ARK => uuid::Uuid::parse_str(&CertType::ARK.to_string()),
            CertType::ASK => uuid::Uuid::parse_str(&CertType::ASK.to_string()),
            CertType::VCEK => uuid::Uuid::parse_str(&CertType::VCEK.to_string()),
            CertType::VLEK => uuid::Uuid::parse_str(&CertType::VLEK.to_string()),
            CertType::CRL => uuid::Uuid::parse_str(&CertType::CRL.to_string()),
            CertType::OTHER(guid) => Ok(guid),
        }
    }
}

impl TryFrom<&uuid::Uuid> for CertType {
    type Error = uuid::Error;

    fn try_from(value: &uuid::Uuid) -> Result<Self, Self::Error> {
        Ok(match value.to_string().as_str() {
            "00000000-0000-0000-0000-000000000000" => CertType::Empty,
            "c0b406a4-a803-4952-9743-3fb6014cd0ae" => CertType::ARK,
            "4ab7b379-bbac-4fe4-a02f-05aef327c782" => CertType::ASK,
            "63da758d-e664-4564-adc5-f4b93be8accd" => CertType::VCEK,
            "a8074bc2-a25a-483e-aae6-39c045a0b8a1" => CertType::VLEK,
            "92f81bc3-5811-4d3d-97ff-d19f88dc67ea" => CertType::CRL,
            _ => CertType::OTHER(*value),
        })
    }
}

impl Ord for CertType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::ARK, Self::ARK)
            | (Self::ASK, Self::ASK)
            | (Self::VCEK, Self::VCEK)
            | (Self::VLEK, Self::VLEK)
            | (Self::CRL, Self::CRL)
            | (Self::Empty, Self::Empty) => std::cmp::Ordering::Equal,
            (Self::OTHER(left), Self::OTHER(right)) => left.cmp(right),
            (Self::Empty, _) => std::cmp::Ordering::Greater,
            (_, Self::Empty) => std::cmp::Ordering::Less,
            (Self::OTHER(_), _) => std::cmp::Ordering::Greater,
            (_, Self::OTHER(_)) => std::cmp::Ordering::Less,
            (Self::CRL, _) => std::cmp::Ordering::Greater,
            (_, Self::CRL) => std::cmp::Ordering::Less,
            (Self::ASK, _) => std::cmp::Ordering::Greater,
            (_, Self::ASK) => std::cmp::Ordering::Less,
            (Self::VLEK, _) => std::cmp::Ordering::Greater,
            (_, Self::VLEK) => std::cmp::Ordering::Less,
            (Self::VCEK, _) => std::cmp::Ordering::Greater,
            (_, Self::VCEK) => std::cmp::Ordering::Less,
        }
    }
}

impl PartialOrd for CertType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
/// An entry with information regarding a specific certificate.
pub struct CertTableEntry {
    /// A Specific certificate type.
    pub cert_type: CertType,

    /// The raw data of the certificate.
    pub data: Vec<u8>,
}

impl CertTableEntry {
    /// Façade for retreiving the GUID for the Entry.
    pub fn guid_string(&self) -> String {
        self.cert_type.to_string()
    }

    /// Get an immutable reference to the data stored in the entry.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Generates a certificate from the str GUID and data provided.
    pub fn from_guid(guid: &uuid::Uuid, data: Vec<u8>) -> crate::error::Result<Self> {
        let cert_type: CertType = match guid.try_into() {
            Ok(guid) => guid,
            Err(error) => return Err(error.into()),
        };
        Ok(Self { cert_type, data })
    }

    /// Generates a certificate from the CertType and data provided.
    pub fn new(cert_type: CertType, data: Vec<u8>) -> Self {
        Self { cert_type, data }
    }

    pub fn vec_bytes_to_cert_table(bytes: &mut [u8]) -> crate::error::Result<Vec<Self>> {
        let cert_bytes_ptr: *mut CertTableEntryRaw = bytes.as_mut_ptr() as *mut CertTableEntryRaw;

        unsafe { CertTableEntryRaw::parse_table(cert_bytes_ptr) }
    }
}

impl Ord for CertTableEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cert_type.cmp(&other.cert_type)
    }
}

impl PartialOrd for CertTableEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cert_type.cmp(&other.cert_type))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct CertTableEntryRaw {
    /// Sixteen character GUID.
    guid: [u8; 16],

    /// The starting location of the certificate blob.
    offset: u32,

    /// The number of bytes to read from the offset.
    length: u32,
}

impl CertTableEntryRaw {
    /// Parses the raw array of bytes into more human understandable information.
    ///
    /// The original C structure looks like this:
    ///
    /// ```C
    /// struct cert_table {
    ///    struct {
    ///       unsigned char guid[16];
    ///       uint32 offset;
    ///       uint32 length;
    ///    } cert_table_entry[];
    /// };
    /// ```
    ///
    pub unsafe fn parse_table(
        mut data: *mut CertTableEntryRaw,
    ) -> crate::error::Result<Vec<CertTableEntry>> {
        // Helpful Constance for parsing the data
        const ZERO_GUID: Uuid = Uuid::from_bytes([0x0; 16]);

        // Pre-defined re-usable variables.
        let table_ptr: *mut u8 = data as *mut u8;

        // Create a location to store the final data.
        let mut retval: Vec<CertTableEntry> = vec![];

        // Start parsing the PSP data from the pointers.
        let mut entry: CertTableEntryRaw;

        loop {
            // Dereference the pointer to parse the table data.
            entry = *data;
            let guid: Uuid = Uuid::from_slice(entry.guid.as_slice())?;

            // Once we find a zeroed GUID, we are done.
            if guid == ZERO_GUID {
                break;
            }

            // Calculate the beginning and ending pointers of the raw certificate data.
            let mut cert_bytes: Vec<u8> = vec![];
            let mut cert_addr: *mut u8 = table_ptr.offset(entry.offset as isize);
            let cert_end: *mut u8 = cert_addr.add(entry.length as usize);

            // Gather the certificate bytes.
            while cert_addr != cert_end {
                cert_bytes.push(*cert_addr);
                cert_addr = cert_addr.add(1usize);
            }

            // Build the Rust-friendly structure and append vector to be returned when
            // we are finished.
            retval.push(CertTableEntry::from_guid(&guid, cert_bytes.clone())?);

            // Move the pointer ahead to the next value.
            data = data.offset(1isize);
        }

        Ok(retval)
    }
}

/// Structure of required data for fetching the derived key.
#[derive(Copy, Clone, Debug)]
pub struct DerivedKey {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,

    /// Reserved, must be zero
    _reserved_0: u32,

    /// What data will be mixed into the derived key.
    pub guest_field_select: GuestFieldSelect,

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

impl DerivedKey {
    /// Create a new instance for requesting an DerivedKey.
    pub fn new(
        root_key_select: bool,
        guest_field_select: GuestFieldSelect,
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
    ) -> Self {
        Self {
            root_key_select: u32::from(root_key_select),
            _reserved_0: Default::default(),
            guest_field_select,
            vmpl,
            guest_svn,
            tcb_version,
        }
    }

    /// Obtain a copy of the root key select value (Private Field)
    pub fn get_root_key_select(&self) -> u32 {
        self.root_key_select
    }
}

bitfield! {
    /// Data which will be mixed into the derived key.
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|GUEST_POLICY|Indicates that the guest policy will be mixed into the key.|
    /// |1|IMAGE_ID|Indicates that the image ID of the guest will be mixed into the key.|
    /// |2|FAMILY_ID|Indicates the family ID of the guest will be mixed into the key.|
    /// |3|MEASUREMENT|Indicates the measurement of the guest during launch will be mixed into the key.|
    /// |4|GUEST_SVN|Indicates that the guest-provided SVN will be mixed into the key.|
    /// |5|TCB_VERSION|Indicates that the guest-provided TCB_VERSION will be mixed into the key.|
    /// |63:6|\-|Reserved. Must be zero.|
    #[repr(C)]
    #[derive(Default, Copy, Clone)]
    pub struct GuestFieldSelect(u64);
    impl Debug;
    /// Check/Set guest policy inclusion in derived key.
    pub get_guest_policy, set_guest_policy: 0, 0;
    /// Check/Set image id inclusion in derived key.
    pub get_image_id, set_image_id: 1, 1;
    /// Check/Set family id inclusion in derived key.
    pub get_family_id, set_family_id: 2, 2;
    /// Check/Set measurement inclusion in derived key.
    pub get_measurement, set_measurement: 3, 3;
    /// Check/Set svn inclusion in derived key.
    pub get_svn, set_svn: 4, 4;
    /// Check/Set tcb version inclusion in derived key.
    pub get_tcb_version, set_tcb_version: 5, 5;
}
