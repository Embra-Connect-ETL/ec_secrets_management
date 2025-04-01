#![allow(unused)]
use dotenvy::dotenv;
use mongodb::{options::ClientOptions, Client, Database};
use rocket::fairing::AdHoc;
use std::{env, sync::Arc};

/*-------------
Custom modules
---------------*/
use crate::repositories::key::KeyRepository;
use crate::repositories::users::UserRepository;
use crate::repositories::vault::VaultRepository;

pub fn init() -> AdHoc {
    AdHoc::on_ignite(
        "Establish connection with Database cluster",
        |rocket| async {
            match connect().await {
                Ok((user_repository, vault_repository, key_repository)) => {
                    rocket.manage(user_repository).manage(vault_repository).manage(key_repository)
                }
                Err(error) => {
                    panic!("Cannot connect to instance:: {:?}", error)
                }
            }
        },
    )
}

async fn connect() -> mongodb::error::Result<(Arc<UserRepository>, Arc<VaultRepository>, Arc<KeyRepository>)> {
    dotenv().ok();

    let database_url = std::env::var_os("ECS_DATABASE_URL")
        .expect("[ECS_DATABASE_URL] must be set...")
        .into_string()
        .unwrap();

    let database_name = std::env::var_os("ECS_DATABASE_NAME")
        .expect("[ECS_DATABASE_NAME] must be set...")
        .into_string()
        .unwrap();

    let client_options = ClientOptions::parse(database_url).await?;
    let client = Client::with_options(client_options)?;
    let database = client.database(&database_name);

    dbg!("Successfully initialized vault database...");

    let user_repo = Arc::new(UserRepository::new(&client, &database_name, "users"));

    let vault_repo = Arc::new(VaultRepository::new(&client, &database_name, "vault"));

    let keys_repo = Arc::new(KeyRepository::new(&client, &database_name, "keys"));

    Ok((user_repo, vault_repo, keys_repo))
}
