#![allow(unused)]

/*-----------------
 3rd party modules
-------------------*/
use chrono::{DateTime, Utc};
use futures::stream::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId},
    error::{Error, Result},
    options::ClientOptions,
    Client, Collection,
};
use serde::{Deserialize, Serialize};

/*--------------
 Custom modules
----------------*/
use crate::models::VaultDocument;
use crate::utils::vault::SecretVault;

#[derive(Debug)]
pub struct VaultRepository {
    collection: Collection<VaultDocument>,
}

impl VaultRepository {
    pub fn new(client: &Client, db_name: &str, collection_name: &str) -> Self {
        let collection = client
            .database(db_name)
            .collection::<VaultDocument>(collection_name);
        Self { collection }
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
        let encryption_key = std::env::var_os("ECS_ENCRYPTION_KEY")
            .expect("[ECS_ENCRYPTION_KEY] must be set...")
            .into_string()
            .unwrap();

        let encrypted_value =
            SecretVault::add_secret(encryption_key, key.to_string(), value.to_string());

        let secret = VaultDocument {
            id: ObjectId::new(),
            key: key.to_string(),
            value: encrypted_value,
            created_by: created_by.to_string(),
            created_at: Utc::now(),
        };

        self.collection.insert_one(&secret).await?;

        Ok(secret)
    }

    /*---------------
    GET secret by id
    ---------------*/
    pub async fn get_secret_by_id(&self, id: &str) -> Result<Option<VaultDocument>> {
        let object_id = ObjectId::parse_str(id).unwrap();
        let filter = doc! { "_id": object_id };
        let secret = self.collection.find_one(filter).await?;
        Ok(secret)
    }

    /*-----------------
    GET secret by author
    -------------------*/
    pub async fn get_secret_by_author(&self, created_by: &str) -> Result<Option<VaultDocument>> {
        let filter = doc! { "created_by": created_by };
        let user = self.collection.find_one(filter).await?;
        Ok(user)
    }

    /*-------------
    DELETE a secret
    ---------------*/
    pub async fn delete_secret(&self, id: &str) -> Result<Option<VaultDocument>> {
        let object_id = ObjectId::parse_str(id).unwrap();
        let filter = doc! { "_id": object_id };
        let secret = self.collection.find_one_and_delete(filter).await?;
        Ok(secret)
    }

    /*-------------
    GET all users
    ---------------*/
    pub async fn list_secrets(&self) -> Result<Vec<VaultDocument>> {
        let filter = doc! {};
        let mut cursor = self.collection.find(filter).await?;
        let mut secrets = Vec::new();

        while let Some(secret) = cursor.try_next().await? {
            secrets.push(secret);
        }

        Ok(secrets)
    }
}
