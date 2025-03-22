#![allow(unused)]
/*-------------
Custom modules
-------------*/
use crate::models::{User, UserCredentials};

/*-----------------
3rd party modules
-----------------*/
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/*-------------
stdlib modules
----------------*/
use std::collections::HashMap;

/*--------------------------------
The following struct will contain
the user's email as a stub
and a timestamp indicating
the time of expiration.
--------------------------------*/
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    nonce: String,    // Unique secret marker
    aud: Vec<String>, // Audience restriction
    iss: String,      // Issuer restriction
}

/*---------------------------------------------
Authorize the user via password verification.
----------------------------------------------*/
pub async fn authorize_user(user: &User, credentials: &UserCredentials) -> Result<String, String> {
    let ecs_authentication_key = std::env::var_os("ECS_AUTHENTICATION_KEY")
        .expect("[ECS_AUTHENTICATION_KEY] must be set...")
        .into_string()
        .unwrap();

    // Verify password using bcrypt
    if !verify(&credentials.password, &user.password).map_err(|e| e.to_string())? {
        return Err("Invalid credentials".into());
    }

    // Generate a unique per-token secret marker
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", user.email, ecs_authentication_key)); // Unique to current system
    let nonce = format!("{:x}", hasher.finalize()); // SHA-256 hashed identifier

    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(480)) // Moderate expiry (8 hrs)
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.email.clone(),
        exp: expiration,
        nonce, // Unique marker
        aud: vec!["https://www.embraconnect.com".to_string()],
        iss: "https://www.embraconnect.com".to_string(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(ecs_authentication_key.as_ref()),
    )
    .map_err(|e| e.to_string())?;

    Ok(token)
}

/*------------------------------------
Standard password hashing via bcrypt.
--------------------------------------*/
pub fn hash_password(password: String) -> Result<String, String> {
    hash(password, DEFAULT_COST).map_err(|e| e.to_string())
}
