#![allow(unused)]
use anyhow::anyhow;
use base64::prelude::BASE64_STANDARD;
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use futures::stream::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId},
    error::Result,
    Client, Collection,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::models::VaultDocument;
use crate::utils::vault::{decrypt, encrypt};

#[derive(Debug)]
pub struct VaultRepository {
    collection: Collection<VaultDocument>,
    encryption_key: String,
}

impl VaultRepository {
    /// Create a new repository with a MongoDB collection and a shared SecretVault instance
    pub fn new(client: &Client, db_name: &str, collection_name: &str) -> Self {
        let collection = client
            .database(db_name)
            .collection::<VaultDocument>(collection_name);

        let encryption_key = format!(
            "{}",
            std::env::var("ECS_ENCRYPTION_KEY").expect("ECS_ENCRYPTION_KEY must be set")
        );

        Self {
            collection,
            encryption_key,
        }
    }

    /*-----------------
    CREATE a new secret
    --------------------*/
    pub async fn create_secret(
        &self,
        key: &str,
        value: &str,
        created_by: &str,
    ) -> Result<VaultDocument> {
        let encrypted_value = encrypt(value.as_bytes(), self.encryption_key.as_bytes()).unwrap();

        let secret = VaultDocument {
            id: ObjectId::new(),
            key: key.to_string(),
            value: general_purpose::STANDARD.encode(encrypted_value), // Use base64 for safe string storage
            created_by: created_by.to_string(),
            created_at: Utc::now(),
        };

        self.collection.insert_one(&secret).await?;
        Ok(secret)
    }

    /*---------------
    GET secret by id
    ---------------*/
    pub async fn get_secret_by_id(&self, id: &str) -> Result<Option<String>> {
        let object_id = ObjectId::parse_str(id).unwrap();
        let filter = doc! { "_id": object_id };

        if let Some(secret) = self.collection.find_one(filter).await? {
            let encoded_value = BASE64_STANDARD.decode(&secret.value).unwrap();
            let decrypted_value = decrypt(&encoded_value, &self.encryption_key.as_bytes()).unwrap();
            return Ok(Some(String::from_utf8_lossy(&decrypted_value).to_string()));
        }
        Ok(None)
    }

    /*-----------------
    GET secret by author
    -------------------*/
    pub async fn get_secret_by_author(&self, created_by: &str) -> Result<Vec<VaultDocument>> {
        let filter = doc! { "created_by": created_by };
        let mut cursor = self.collection.find(filter).await?;
        let mut secrets = Vec::new();

        while let Some(mut secret) = cursor.try_next().await? {
            if let Ok(encoded_value) = BASE64_STANDARD.decode(&secret.value) {
                if let Ok(decrypted_value) = decrypt(&encoded_value, self.encryption_key.as_bytes())
                {
                    secret.value = String::from_utf8_lossy(&decrypted_value).to_string();
                }
            }
            secrets.push(secret);
        }

        Ok(secrets)
    }

    /*-------------
    DELETE a secret
    ---------------*/
    pub async fn delete_secret(&self, id: &str) -> Result<Option<String>> {
        let object_id = ObjectId::parse_str(id).unwrap();
        let filter = doc! { "_id": object_id };

        if let Some(secret) = self.collection.find_one_and_delete(filter).await? {
            let encoded_value = BASE64_STANDARD.decode(&secret.value).unwrap();
            let decrypted_value = decrypt(&encoded_value, &self.encryption_key.as_bytes()).unwrap();
            return Ok(Some(String::from_utf8_lossy(&decrypted_value).to_string()));
        }

        Ok(None)
    }

    /*-------------
    LIST all secrets
    ---------------*/
    pub async fn list_secrets(&self) -> Result<Vec<VaultDocument>> {
        let mut cursor = self.collection.find(doc! {}).await?;
        let mut secrets = Vec::new();

        while let Some(mut secret) = cursor.try_next().await? {
            if let Ok(encoded_value) = BASE64_STANDARD.decode(&secret.value) {
                if let Ok(decrypted_value) = decrypt(&encoded_value, self.encryption_key.as_bytes())
                {
                    secret.value = String::from_utf8_lossy(&decrypted_value).to_string();
                }
            }
            secrets.push(secret);
        }

        Ok(secrets)
    }
}
