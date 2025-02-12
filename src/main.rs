use std::str::FromStr;

use alloy::consensus::{SignableTransaction, TxLegacy};
use alloy::network::TxSigner;
use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder};
use alloy_signer::GcpRestSigner;
use common::GcpKeyRef;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{ClientBuilder, Url};
use solana_sdk::message::Message;
use solana_sdk::signer::Signer;
use solana_sdk::system_instruction;
use solana_sdk::transaction::Transaction;
use tokio::time::Instant;

mod iam;
mod common;
mod solana_signer;
mod alloy_signer;

const PROJECT_ID: &str = "keymanagertest-449901";
const LOCATION_ID: &str = "asia1";


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    evm_test().await;
}

#[allow(dead_code)]
async fn evm_test() {
    let iam_json = iam::load_iam_json("keymanagertest-449901-852e5e8d054d.json").unwrap();
    let token = iam::get_oauth2_token(&iam_json).await.unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", token)).unwrap());

    let start_time = Instant::now();

    let client = ClientBuilder::new()
        .default_headers(headers)
        .build()
        .unwrap();

    let time_1 = Instant::now();
    tracing::info!("Client created in {:?}", time_1.duration_since(start_time));

    let key = GcpKeyRef {
        project_id: PROJECT_ID.to_string(),
        location: LOCATION_ID.to_string(),
        key_name: "test1".to_string(),
        version: 1,
        key_ring: "evm_test_1".to_string(),
    };

    let signer = GcpRestSigner::new_with_client(client, key, None).await.unwrap();
    tracing::info!("Address: {}", signer.address());

    let time_2 = Instant::now();
    tracing::info!("Signer created in {:?}", time_2.duration_since(time_1));

    // Sepolia test net
    let chain_id = 11155111;
    let mut tx = TxLegacy {
        to: signer.address().into(),
        value: U256::from(1_000_000_000),
        gas_limit: 21000,
        nonce: 11,
        gas_price: 100_000_000_000,
        input: vec![].into(),
        chain_id: Some(chain_id),
    };

    let signature = signer.sign_transaction(&mut tx).await.unwrap();

    let time_3 = Instant::now();
    tracing::info!("Transaction signed in {:?}", time_3.duration_since(time_2));

    let tx = tx.into_signed(signature);

    let client = alloy::rpc::client::RpcClient::new_http(Url::from_str("https://1rpc.io/sepolia").unwrap());
    let provider = ProviderBuilder::new().on_client(client);
    let res = provider.send_tx_envelope(tx.into()).await.unwrap();

    let time_4 = Instant::now();
    tracing::info!("Transaction sent in {:?}", time_4.duration_since(time_3));

    println!("Tx hash: {:?}", res);
}

#[allow(dead_code)]
async fn solana_test() {
    let iam_json = iam::load_iam_json("keymanagertest-449901-852e5e8d054d.json").unwrap();
    let token = iam::get_oauth2_token(&iam_json).await.unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", token)).unwrap());

    let start = Instant::now();
    let client = ClientBuilder::new()
        .default_headers(headers)
        .build()
        .unwrap();

    let key = GcpKeyRef {
        project_id: PROJECT_ID.to_string(),
        location: LOCATION_ID.to_string(),
        key_name: "test2".to_string(),
        version: 1,
        key_ring: "solana_test_1".to_string(),
    };

    let signer = solana_signer::GcpSigner {
        client,
        key,
    };

    let time_1 = Instant::now();
    tracing::info!("Client created in {:?}", time_1.duration_since(start));

    let solana_client = solana_client::rpc_client::RpcClient::new("https://api.devnet.solana.com");
    let block = solana_client.get_latest_blockhash().unwrap();

    let time_2 = Instant::now();
    tracing::info!("Solana client created in {:?}", time_2.duration_since(time_1));

    let address = signer.try_pubkey().unwrap();
    println!("Address: {}", address);

    let time_3 = Instant::now();
    tracing::info!("Address fetched in {:?}", time_3.duration_since(time_2));

    let transfer_instruction = system_instruction::transfer(&address, &address, 1_000_000_000);
    let tx = Transaction::new(&[signer], Message::new(&[transfer_instruction], Some(&address)), block);
    tx.verify().unwrap();

    let time_4 = Instant::now();
    tracing::info!("Transaction created in {:?}", time_4.duration_since(time_3));

    let signature = solana_client.send_and_confirm_transaction(&tx).unwrap();
    println!("TX Signature: {}", signature);
}
