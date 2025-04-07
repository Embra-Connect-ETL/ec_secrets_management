use crate::models::KeyPairDocument;

use base64::{engine::general_purpose, Engine as _};
use bson::doc;
use chrono::{Duration, Utc};
use mongodb::{Client, Collection};
use pasetors::{
    keys::{Generate, SymmetricKey},
    version4::V4,
};

/*---------------------------------------------------------------------------
    The KeyRepository provides a basic secrets management mechanism that
    generates and stores cryptographically secure symmetric keys for
    authentication or encryption purposes.

    Note: While this struct is called KeyPairDocument,
    it currently only stores a symmetric key.
---------------------------------------------------------------------------*/
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
        let kp = SymmetricKey::<V4>::generate().map_err(|e| e.to_string())?;
        let private_key = general_purpose::STANDARD.encode(kp.as_bytes());
        let key_pair = KeyPairDocument {
            private_key,
            created_at: Utc::now(),
        };
        let valid_age = Utc::now() - Duration::days(1);
        let mut cursor = self
            .collection
            .find_one(doc! {})
            .await
            .map_err(|e| e.to_string())?;
        if let Some(doc) = cursor {
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
