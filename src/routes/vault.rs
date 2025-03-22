/*-------------
Custom modules
--------------*/
use crate::models::*;
use crate::repositories::vault::VaultRepository;

/*-------------
3rd party modules
--------------*/
use log::{debug, error, info, warn};
use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::{json::Json, Deserialize};
use rocket::{delete, get, post, put, routes, State};

/*-------------
stdlib modules
--------------*/
use std::sync::Arc;

/*---------------------
 Create a vault entry
---------------------*/
#[post("/create/vault/entry", data = "<secret>")]
pub async fn create_secret(
    repo: &State<Arc<VaultRepository>>,
    secret: Json<Secret>,
) -> Result<Json<CreateSecretResponse>, Json<ErrorResponse>> {
    match repo
        .create_secret(&secret.key, &secret.value, &secret.created_by)
        .await
    {
        Ok(_) => {
            info!("Vault entry created successfully.");
            Ok(Json(CreateSecretResponse {
                status: Status::Ok.code,
                message: "Vault entry created successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to create vault entry: {:?}", e);
            Err(Json(ErrorResponse {
                status: Status::InternalServerError.code,
                message: "Failed to create vault entry".to_string(),
            }))
        }
    }
}

/*--------------------------
 Retrieve all vault entries
---------------------------*/
#[get("/retrieve/vault/entries")]
pub async fn list_entries(
    repo: &State<Arc<VaultRepository>>,
) -> Result<Json<Vec<VaultDocument>>, Json<ErrorResponse>> {
    match repo.list_secrets().await {
        Ok(entries) if !entries.is_empty() => {
            info!("Successfully retrieved {} vault entries.", entries.len());
            Ok(Json(entries))
        }
        Ok(_) => {
            warn!("No vault entries found.");
            Err(Json(ErrorResponse {
                status: Status::NotFound.code,
                message: "No vault entries found.".to_string(),
            }))
        }
        Err(_) => {
            error!("Failed to retrieve vault entries.");
            Err(Json(ErrorResponse {
                status: Status::InternalServerError.code,
                message: "Failed to retrieve vault entries.".to_string(),
            }))
        }
    }
}

/*-----------------------------
 Retrieve a vault entry by id
------------------------------*/
#[get("/retrieve/vault/entries/<id>")]
pub async fn get_entry(
    repo: &State<Arc<VaultRepository>>,
    id: &str,
) -> Result<Json<String>, Json<ErrorResponse>> {
    if id.trim().is_empty() {
        error!("Invalid request: Provided ID is empty.");
        return Err(Json(ErrorResponse {
            status: Status::BadRequest.code,
            message: "Invalid ID provided.".to_string(),
        }));
    }

    match repo.get_secret_by_id(&id).await {
        Ok(Some(entry)) => {
            info!("Successfully retrieved vault entry with ID: {}", id);
            Ok(Json(entry))
        }
        Ok(None) => {
            error!("Vault entry not found with ID: {}", id);
            Err(Json(ErrorResponse {
                status: Status::NotFound.code,
                message: "Vault entry not found.".to_string(),
            }))
        }
        Err(e) => {
            error!(
                "Failed to retrieve vault entry by ID: {}. Error: {:?}",
                id, e
            );
            Err(Json(ErrorResponse {
                status: Status::InternalServerError.code,
                message: "Failed to retrieve vault entry.".to_string(),
            }))
        }
    }
}

/*---------------------------------
 Retrieve a vault entry by author
----------------------------------*/
#[get("/retrieve/vault/entry/<created_by>")]
pub async fn get_entry_by_author(
    repo: &State<Arc<VaultRepository>>,
    created_by: &str,
) -> Result<Json<Vec<VaultDocument>>, Json<ErrorResponse>> {
    if created_by.trim().is_empty() {
        error!("Invalid request: Provided author name is empty.");
        return Err(Json(ErrorResponse {
            status: Status::BadRequest.code,
            message: "Invalid author name provided.".to_string(),
        }));
    }

    match repo.get_secret_by_author(created_by).await {
        Ok(secrets) if !secrets.is_empty() => {
            info!(
                "Successfully retrieved {} vault entries for author: {}",
                secrets.len(),
                created_by
            );
            Ok(Json(secrets))
        }
        Ok(_) => {
            error!("No vault entries found for author: {}", created_by);
            Err(Json(ErrorResponse {
                status: Status::NotFound.code,
                message: "No vault entries found.".to_string(),
            }))
        }
        Err(e) => {
            error!(
                "Failed to retrieve vault entries for author: {}. Error: {:?}",
                created_by, e
            );
            Err(Json(ErrorResponse {
                status: Status::InternalServerError.code,
                message: "Failed to retrieve vault entries.".to_string(),
            }))
        }
    }
}

/*---------------------
 Delete a vault entry
----------------------*/
#[delete("/delete/<id>")]
pub async fn delete_entry(
    repo: &State<Arc<VaultRepository>>,
    id: &str,
) -> Result<Json<DeleteSecretResponse>, Json<ErrorResponse>> {
    if id.trim().is_empty() || id.contains(char::is_whitespace) {
        error!("Invalid request: Provided ID '{}' is invalid.", id);
        return Err(Json(ErrorResponse {
            status: Status::BadRequest.code,
            message: "Invalid ID provided for deletion.".to_string(),
        }));
    }

    match repo.delete_secret(&id).await {
        Ok(Some(_)) => {
            info!("Successfully deleted vault entry with ID: {}", id);
            Ok(Json(DeleteSecretResponse {
                status: Status::Ok.code,
                message: "Vault entry deleted successfully.".to_string(),
            }))
        }
        Ok(None) => {
            error!("Vault entry not found for deletion with ID: {}", id);
            Err(Json(ErrorResponse {
                status: Status::NotFound.code,
                message: "Vault entry not found.".to_string(),
            }))
        }
        Err(e) => {
            error!(
                "Failed to delete vault entry with ID: {}. Error: {:?}",
                id, e
            );
            Err(Json(ErrorResponse {
                status: Status::InternalServerError.code,
                message: "Failed to delete vault entry.".to_string(),
            }))
        }
    }
}

pub fn vault_routes() -> Vec<rocket::Route> {
    routes![
        create_secret,
        list_entries,
        get_entry,
        get_entry_by_author,
        delete_entry
    ]
}
