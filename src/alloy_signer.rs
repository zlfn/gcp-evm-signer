use alloy::{consensus::SignableTransaction, primitives::{Address, ChainId, FixedBytes, PrimitiveSignature, B256}, signers::{sign_transaction_with_chain_id, Signer}};
use async_trait::async_trait;
use base64::{prelude::BASE64_STANDARD, Engine};
use spki::DecodePublicKey;
use k256::ecdsa::VerifyingKey;
use crate::common::{Digest, GcpKeyRef, SignRequest, SignResponse};

#[derive(Clone)]
#[allow(dead_code)]
pub struct GcpRestSigner {
    // client with oauth2 token
    client: reqwest::Client,
    key: GcpKeyRef,

    chain_id: Option<ChainId>,
    pubkey: VerifyingKey,
    address: Address
}

#[derive(Debug, thiserror::Error)]
pub enum GcpRestSignerError {
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl alloy::network::TxSigner<PrimitiveSignature> for GcpRestSigner {
    fn address(&self) -> Address {
        self.address
    }

    #[inline]
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<PrimitiveSignature>
    ) -> Result<alloy::primitives::PrimitiveSignature, alloy::signers::Error> {
        sign_transaction_with_chain_id!(self, tx, self.sign_hash(&tx.signature_hash()).await)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Signer for GcpRestSigner {
    async fn sign_hash(&self, hash: &B256) -> Result<alloy::primitives::PrimitiveSignature, alloy::signers::Error> {
        Ok(self.sign_digest(*hash).await.unwrap())
    }
    fn address(&self) -> Address {
        self.address
    }
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}


impl GcpRestSigner {
    pub async fn new_with_client(
        client: reqwest::Client,
        key: GcpKeyRef,
        chain_id: Option<ChainId>,
    ) -> Result<Self, GcpRestSignerError> {
        let pubkey = Self::get_pubkey(client.clone(), key.clone()).await?;
        Ok(Self {
            client,
            key,
            chain_id,
            pubkey,
            address: alloy::signers::utils::public_key_to_address(&pubkey)
        })
    }

    pub async fn get_pubkey(client: reqwest::Client, key: GcpKeyRef) -> Result<VerifyingKey, GcpRestSignerError> {
        let pem = client.get(&format!(
            "https://cloudkms.googleapis.com/v1/{}/publicKey",
            key.to_specifier()
        )).send().await.unwrap().json::<serde_json::Value>().await.unwrap();
        let pem = pem["pem"].as_str().unwrap();

        Ok(VerifyingKey::from_public_key_pem(&pem).unwrap())
    }

    pub async fn sign_digest(&self, digest: B256) -> Result<PrimitiveSignature, GcpRestSignerError> {
        let digest_string = Digest::Sha256(BASE64_STANDARD.encode(digest.as_slice()));
        let request = SignRequest::DIGEST {
            digest: digest_string,
            digest_crc32c: None
        };

        let response = self.client.post(&format!(
            "https://cloudkms.googleapis.com/v1/{}:asymmetricSign",
            self.key.to_specifier()
        )).json(&request).send().await.unwrap();
        let response = response.json::<SignResponse>().await.unwrap();

        let sig_bytes = BASE64_STANDARD.decode(response.signature).unwrap();
        let sig: asn1::ParseResult<_> = asn1::parse(&sig_bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let r = d.read_element::<asn1::BigUint>()?.as_bytes().to_vec();
                let s = d.read_element::<asn1::BigUint>()?.as_bytes().to_vec();
                Ok((r, s))
            })
        });
        let sig = sig.unwrap();

        let primitive = PrimitiveSignature::from_scalars_and_parity(
            FixedBytes::from_slice(Self::trim_leading_zero(&sig.0)), 
            FixedBytes::from_slice(Self::trim_leading_zero(&sig.1)), 
            false
        );
        if Self::check_candidate(&primitive, &digest, &self.pubkey) {
            return Ok(primitive);
        }

        let primitive = primitive.with_parity(true);
        if Self::check_candidate(&primitive, &digest, &self.pubkey) {
            return Ok(primitive);
        }

        panic!("bad signature");
    }

    fn check_candidate(signature: &PrimitiveSignature, hash: &B256, pubkey: &VerifyingKey) -> bool {
        signature.recover_from_prehash(hash).map(|key| key == *pubkey).unwrap_or(false)
    }

    fn trim_leading_zero(bytes: &[u8]) -> &[u8] {
        if bytes.len() == 33 && bytes[0] == 0 {
            &bytes[1..]
        } else {
            bytes
        }
    }
}

