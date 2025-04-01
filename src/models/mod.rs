use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use pasetors::{
    keys::{AsymmetricPublicKey, AsymmetricSecretKey},
    version4::V4,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/*------------
 User models
-------------*/
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserDocument {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub email: String,
    pub password: String,
    #[serde(
        with = "bson::serde_helpers::chrono_datetime_as_bson_datetime",
        rename = "createdAt"
    )]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyPairDocument {
    pub public_key: String,
    pub private_key: String,
    #[serde(
        with = "bson::serde_helpers::chrono_datetime_as_bson_datetime",
        rename = "createdAt"
    )]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct User {
    #[serde(rename = "_id")]
    pub id: String,
    pub email: String,
    pub password: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct UserCredentials {
    pub email: String,
    pub password: String,
}

/*------------
 Vault models
-------------*/
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultDocument {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub key: String,
    pub value: String,
    pub created_by: String,
    #[serde(
        with = "bson::serde_helpers::chrono_datetime_as_bson_datetime",
        rename = "createdAt"
    )]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct Vault {
    #[serde(rename = "_id")]
    pub id: String,
    pub key: String,
    pub value: String,
    pub created_by: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Secret {
    pub key: String,
    pub value: String,
    pub created_by: String,
}

/*----------
 Responses
----------*/
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecretResponse {
    pub status: u16,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteSecretResponse {
    pub status: u16,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: u16,
    pub message: String,
}

#[derive(Debug, Deserialize, Responder, Serialize)]
pub struct AuthModuleResponse {
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetupResponse {
    pub status: u16,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResponse {
    pub status: u16,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteUserResponse {
    pub status: u16,
    pub message: String,
}
