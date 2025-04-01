use std::sync::Arc;

use base64::{engine::general_purpose, Engine as _};
use bcrypt::verify;
use chrono::{Duration, Utc};
use pasetors::{
    claims::Claims,
    keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate},
    public,
    version4::V4,
};
use rocket::State;
use sha2::{Digest, Sha256};

use crate::{
    models::{User, UserCredentials},
    repositories::{self, key::KeyRepository},
};

async fn decode_keys(
    repo: &State<Arc<KeyRepository>>,
) -> Result<(AsymmetricSecretKey<V4>, AsymmetricPublicKey<V4>), String> {
    let kp = repo.get_or_create_key_pair().await?;
    let private_key_bytes = general_purpose::STANDARD
        .decode(kp.private_key)
        .map_err(|e| e.to_string())?;
    let private_key =
        AsymmetricSecretKey::<V4>::from(&private_key_bytes).map_err(|e| e.to_string())?;
    let public_key_bytes = general_purpose::STANDARD
        .decode(kp.public_key)
        .map_err(|e| e.to_string())?;
    let public_key =
        AsymmetricPublicKey::<V4>::from(&public_key_bytes).map_err(|e| e.to_string())?;
    let kp = (private_key, public_key);
    Ok(kp)
}

pub async fn authorize_user(
    user: &User,
    credentials: &UserCredentials,
    repo: &State<Arc<KeyRepository>>,
) -> Result<String, String> {
    if !verify(&credentials.password, &user.password).map_err(|e| e.to_string())? {
        return Err("Invalid credentials".into());
    }
    let mut claims = Claims::new().map_err(|e| e.to_string())?;
    let ecs_authentication_key = std::env::var_os("ECS_AUTHENTICATION_KEY")
        .expect("[ECS_AUTHENTICATION_KEY] must be set...")
        .into_string()
        .unwrap();

    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(480)) // Moderate expiry (8 hrs)
        .expect("valid timestamp")
        .timestamp() as usize;

    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", user.email, ecs_authentication_key)); // Unique to current system
    let nonce = format!("{:x}", hasher.finalize());

    claims.subject(&credentials.email);
    claims.expiration(&expiration.to_string());
    claims.issuer("https://www.embraconnect.com");
    claims.add_additional("nonce", nonce);
    claims.add_additional("aud", vec!["https://www.embraconnect.com".to_string()]);
    let kp = decode_keys(repo).await?;
    let token = public::sign(&kp.0, &claims, None, None).map_err(|e| e.to_string())?;
    Ok(token)
}
