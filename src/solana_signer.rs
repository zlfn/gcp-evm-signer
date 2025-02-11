use base64::{prelude::BASE64_STANDARD, Engine};
use solana_sdk::pubkey::Pubkey;

use crate::common::{GcpKeyRef, SignRequest, SignResponse};

pub struct GcpSigner {
    pub client: reqwest::Client,
    pub key: GcpKeyRef,
}

impl solana_sdk::signer::Signer for GcpSigner {
    fn try_pubkey(&self) -> Result<solana_sdk::pubkey::Pubkey, solana_sdk::signer::SignerError> {
        let pem = tokio::task::block_in_place(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let pem = self.client.get(&format!(
                    "https://cloudkms.googleapis.com/v1/{}/publicKey",
                    self.key.to_specifier()
                )).send().await.unwrap().json::<serde_json::Value>().await.unwrap();
                let pem = pem["pem"].as_str().unwrap();
                pem::parse(&pem).unwrap()
            })
        });

        Ok(Pubkey::new_from_array(pem.contents()[12..].try_into().unwrap()))
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<solana_sdk::signature::Signature, solana_sdk::signer::SignerError> {
        let req = SignRequest::DATA {
            data: BASE64_STANDARD.encode(message),
            data_crc32c: None,
        };

        let resp = tokio::task::block_in_place(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                self.client.post(&format!(
                    "https://cloudkms.googleapis.com/v1/{}:asymmetricSign",
                    self.key.to_specifier()
                )).json(&req).send().await.unwrap().json::<SignResponse>().await.unwrap()
            })
        });

        let sig: [u8; 64] = BASE64_STANDARD.decode(resp.signature).unwrap().try_into().unwrap();
        Ok(sig.into())
    }

    fn is_interactive(&self) -> bool {
        false
    }
}
