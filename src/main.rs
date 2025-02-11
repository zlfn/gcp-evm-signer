use common::GcpKeyRef;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::ClientBuilder;
use solana_client::rpc_client::RpcClient;
use solana_sdk::message::Message;
use solana_sdk::signer::Signer;
use solana_sdk::system_instruction;
use solana_sdk::transaction::Transaction;

mod iam;
mod common;
mod solana_signer;
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
        key_name: "test2".to_string(),
        version: 1,
        key_ring: "solana_test_1".to_string(),
    };

    let solana_client = RpcClient::new("https://api.devnet.solana.com");
    let block = solana_client.get_latest_blockhash().unwrap();

    let signer = solana_signer::GcpSigner {
        client,
        key,
    };

    let address = signer.try_pubkey().unwrap();
    println!("Address: {}", address);

    let transfer_instruction = system_instruction::transfer(&address, &address, 1_000_000_000);
    let tx = Transaction::new(&[signer], Message::new(&[transfer_instruction], Some(&address)), block);
    tx.verify().unwrap();

    let signature = solana_client.send_and_confirm_transaction(&tx).unwrap();
    println!("TX Signature: {}", signature);
}
