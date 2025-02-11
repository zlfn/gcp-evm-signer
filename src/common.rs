use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct GcpKeyRef {
    pub project_id: String,
    pub location: String,
    pub version: u64,
    pub key_ring: String,
    pub key_name: String,
}

impl GcpKeyRef {
    pub fn to_specifier(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
            self.project_id, self.location, self.key_ring, self.key_name, self.version
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Digest {
    Sha256(String),
    Sha384(String),
    Sha512(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum SignRequest {
    DIGEST {
        digest: Digest,
        digest_crc32c: Option<String>
    },
    DATA {
        data: String,
        data_crc32c: Option<String>
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignResponse {
    pub name: String,
    pub signature: String,
    pub signature_crc32c: String,
    pub protection_level: String,
}
