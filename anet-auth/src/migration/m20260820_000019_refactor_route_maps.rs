use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Удаляем устаревшую промежуточную таблицу привязок
        manager
            .drop_table(Table::drop().table(Alias::new("user_route_maps")).to_owned())
            .await?;

        // 2. Добавляем колонку route_map_id напрямую в таблицу пользователей
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .add_column(ColumnDef::new(Alias::new("route_map_id")).uuid().null())
                    .to_owned(),
            )
            .await?;

        // 3. Создаем внешний ключ со связью ON DELETE SET NULL
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk-users-route-map")
                    .from(Alias::new("users"), Alias::new("route_map_id"))
                    .to(Alias::new("route_maps"), Alias::new("id"))
                    .on_delete(ForeignKeyAction::SetNull)
                    .on_update(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        // 4. Наполняем базу данных тремя глобальными пресетами с фиксированными UUID
        let db = manager.get_connection();
        let now = chrono::Utc::now().naive_utc().to_string();

        // Пресет 1: "Full Tunnel" (id: ...01)
        // Направляет все в туннель, исключая локальные подсети
        let sql_full_tunnel = format!(
            "INSERT INTO route_maps (id, name, description, default_action, is_active, revision, created_at, updated_at) \
             VALUES ('00000000-0000-4000-a000-000000000001', 'Full Tunnel', 'Направляет весь интернет-трафик в VPN-туннель, исключая локальные сети.', 'tunnel', true, 1, '{now}', '{now}')"
        );
        db.execute_unprepared(&sql_full_tunnel).await?;

        // Дефолтные правила исключений для Full Tunnel (прямые маршруты для локальных сетей)
        let local_rules = vec![
            ("192.168.0.0/16", 0),
            ("10.0.0.0/8", 1),
            ("172.16.0.0/12", 2),
        ];
        for (cidr, pos) in local_rules {
            let rule_id = uuid::Uuid::new_v4().to_string();
            let sql_rule = format!(
                "INSERT INTO route_rules (id, route_map_id, position, match_type, match_value, action) \
                 VALUES ('{rule_id}', '00000000-0000-4000-a000-000000000001', {pos}, 'cidr', '{cidr}', 'direct')"
            );
            db.execute_unprepared(&sql_rule).await?;
        }

        // Пресет 2: "WhiteList Bypass" (id: ...02)
        // Направляет в туннель только ресурсы из белого списка, остальное — напрямую
        let sql_whitelist = format!(
            "INSERT INTO route_maps (id, name, description, default_action, is_active, revision, created_at, updated_at) \
             VALUES ('00000000-0000-4000-a000-000000000002', 'WhiteList Bypass', 'Направляет в VPN-туннель только ресурсы из белого списка. Весь остальной трафик идет напрямую.', 'direct', true, 1, '{now}', '{now}')"
        );
        db.execute_unprepared(&sql_whitelist).await?;

        // Пресет 3: "Gaming" (id: ...03)
        // Направляет в туннель только игровые сервера
        let sql_gaming = format!(
            "INSERT INTO route_maps (id, name, description, default_action, is_active, revision, created_at, updated_at) \
             VALUES ('00000000-0000-4000-a000-000000000003', 'Gaming', 'Направляет в VPN только игровые сервисы (Steam, PSN, Xbox Live) для снижения пинга.', 'direct', true, 1, '{now}', '{now}')"
        );
        db.execute_unprepared(&sql_gaming).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk-users-route-map")
                    .table(Alias::new("users"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .drop_column(Alias::new("route_map_id"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Alias::new("user_route_maps"))
                    .if_not_exists()
                    .col(ColumnDef::new(Alias::new("user_id")).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Alias::new("route_map_id")).uuid().not_null())
                    .to_owned()
            )
            .await?;

        Ok(())
    }
}
