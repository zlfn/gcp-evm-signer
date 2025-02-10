use std::str::FromStr;

use alloy::{consensus::{SignableTransaction, TxLegacy}, network::TxSigner, primitives::U256, providers::{Provider, ProviderBuilder}, rpc::client::RpcClient};
use alloy_signer::{GcpKeyRef, GcpRestSigner};
use reqwest::{header::{HeaderMap, HeaderValue}, ClientBuilder, Url};

mod iam;
mod alloy_signer;

const PROJECT_ID: &str = "keymanagertest-449901";
const LOCATION_ID: &str = "asia1";


#[tokio::main]
async fn main() {
    let iam_json = iam::load_iam_json("keymanagertest-449901-852e5e8d054d.json").unwrap();
    let token = iam::get_oauth2_token(&iam_json).await.unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", token)).unwrap());

    let client = ClientBuilder::new()
        .default_headers(headers)
        .build()
        .unwrap();

    let key = GcpKeyRef {
        project_id: PROJECT_ID.to_string(),
        location: LOCATION_ID.to_string(),
        key_name: "test1".to_string(),
        version: 1,
        key_ring: "evm_test_1".to_string(),
    };

    let signer = GcpRestSigner::new_with_client(client, key, None).await.unwrap();
    println!("Address: {}", signer.address());

    // Sepolia test net
    let chain_id = 11155111;
    let mut tx = TxLegacy {
        to: signer.address().into(),
        value: U256::from(1_000_000_000),
        gas_limit: 21000,
        nonce: 9,
        gas_price: 100_000_000_000,
        input: vec![].into(),
        chain_id: Some(chain_id),
    };

    let signature = signer.sign_transaction(&mut tx).await.unwrap();
    println!("Signed!");
    let tx = tx.into_signed(signature);

    let client = RpcClient::new_http(Url::from_str("https://1rpc.io/sepolia").unwrap());
    let provider = ProviderBuilder::new().on_client(client);
    let res = provider.send_tx_envelope(tx.into()).await.unwrap();

    println!("Tx hash: {:?}", res);
}
