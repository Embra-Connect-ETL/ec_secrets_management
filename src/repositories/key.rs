use crate::models::KeyPairDocument;

use base64::{engine::general_purpose, Engine as _};
use bson::{doc, from_document, oid::ObjectId, DateTime};
use chrono::{Duration, Utc};
use futures::{StreamExt, TryStreamExt};
use mongodb::{Client, Collection};
use pasetors::{
    keys::{AsymmetricKeyPair, Generate},
    version4::V4,
};

pub struct KeyRepository {
    collection: Collection<KeyPairDocument>,
}

impl KeyRepository {
    pub fn new(client: &Client, db_name: &str, collection_name: &str) -> Self {
        let collection = client
            .database(db_name)
            .collection::<KeyPairDocument>(collection_name);
        Self { collection }
    }

    pub async fn get_or_create_key_pair(&self) -> Result<KeyPairDocument, String> {
        let kp = AsymmetricKeyPair::<V4>::generate().map_err(|e| e.to_string())?;
        let public_key = general_purpose::STANDARD.encode(kp.public.as_bytes());
        let private_key = general_purpose::STANDARD.encode(kp.secret.as_bytes());
        let key_pair = KeyPairDocument {
            public_key,
            private_key,
            created_at: Utc::now(),
        };
        let valid_age = Utc::now() - Duration::days(1);
        let mut cursor = self
            .collection
            .find(doc! { "created_at": {"$lt": DateTime::from(valid_age)} })
            .await
            .map_err(|e| e.to_string())?;
        if let Some(doc) = cursor.try_next().await.map_err(|e| e.to_string())? {
            return Ok(doc);
        } else {
            self.collection
                .insert_one(key_pair.clone())
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(key_pair)
    }
}
