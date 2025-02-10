use std::fs::File;

use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::Client;

pub fn load_iam_json(file_path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let json: serde_json::Value = serde_json::from_reader(file)?;
    Ok(json)
}

pub async fn get_oauth2_token(iam: &serde_json::Value) -> Result<String, eyre::Error> {
    let token = generate_jwt(iam)?;
    let params = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": token,
    });
    let client = Client::new();
    let response = client.post("https://oauth2.googleapis.com/token")
        .json(&params)
        .send()
        .await
        .unwrap();
    let json: serde_json::Value = response.json().await.unwrap();
    let token = json["access_token"].clone();

    Ok(token.to_string())
}

fn generate_jwt(iam: &serde_json::Value) -> Result<String, eyre::Error> {
    let private_key = iam["private_key"].as_str().unwrap();
    let client_email = iam["client_email"].as_str().unwrap();
    let now = Utc::now();
    let exp = now + chrono::Duration::hours(1);

    let claims = serde_json::json!({
        "iss": client_email,
        "sub": client_email,
        "scope": "https://www.googleapis.com/auth/cloudkms",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now.timestamp(),
        "exp": exp.timestamp(),
    });

    let header = Header::new(jsonwebtoken::Algorithm::RS256);
    let key = EncodingKey::from_rsa_pem(private_key.as_bytes())?;
    let token = encode(&header, &claims, &key)?;

    Ok(token)
}
