use anyhow::Result;
use directories::ProjectDirs;
use sea_orm::{Database, DatabaseConnection};
use std::fs;
use sea_orm_migration::MigratorTrait;

use crate::migration;

#[derive(Clone)]
pub struct AnetDB {
}

impl AnetDB {

    pub async fn connect_db(url : Option<String>) -> Result<DatabaseConnection, sea_orm::DbErr> {
        let db_url = match url{
            Some(url) => url,
            None => {
                // ~/.local/share/myapp/
                let proj_dirs = ProjectDirs::from("org", "alco","anet")
                    .expect("failed to get project dirs");

                let data_dir = proj_dirs.data_dir();

                fs::create_dir_all(data_dir).expect("failed to create data dir");

                let db_path = data_dir.join("db.sqlite");

                format!("sqlite://{}?mode=rwc", db_path.display())
            }
        };

        println!("DB: {}", db_url);

        
        let db: DatabaseConnection =
            Database::connect(db_url)
                .await?;

        migration::Migrator::up(&db, None).await?;
        Ok(db)
    }
}
