use chrono::Utc;
use poem::http::StatusCode;
use poem_openapi::{
    param::{Path, Query},
    payload::Json,
    Object, OpenApi,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::api::validate_admin_session;
use crate::api::dto::AdminToken;
use crate::entities::{
    billing_enums::{Currency, OrderStatus, PaymentSystem, ProductType},
    orders, products, transactions,
};

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct AdminProductDto {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub price: f64,
    pub currency: Currency,
    pub product_type: ProductType,
    pub target_id: Option<Uuid>,
    pub sort_order: i32,
    pub badge: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<products::Model> for AdminProductDto {
    fn from(p: products::Model) -> Self {
        Self {
            id: p.id,
            name: p.name,
            description: p.description,
            price: p.price,
            currency: p.currency,
            product_type: p.product_type,
            target_id: p.target_id,
            sort_order: p.sort_order,
            badge: p.badge,
            metadata: p.metadata,
            is_active: p.is_active,
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct CreateProductRequest {
    pub name: String,
    pub description: String,
    pub price: f64,
    pub currency: Currency,
    pub product_type: ProductType,
    pub target_id: Option<Uuid>,
    pub sort_order: Option<i32>,
    pub badge: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_active: bool,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct UpdateProductRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price: Option<f64>,
    pub currency: Option<Currency>,
    pub product_type: Option<ProductType>,
    pub target_id: Option<Option<Uuid>>,
    pub sort_order: Option<i32>,
    pub badge: Option<Option<String>>,
    pub metadata: Option<Option<serde_json::Value>>,
    pub is_active: Option<bool>,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct AdminOrderDto {
    pub id: Uuid,
    pub user_id: Uuid,
    pub product_id: Uuid,
    pub amount: f64,
    pub currency: Currency,
    pub status: OrderStatus,
    pub is_gift: bool,
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct PaginatedOrdersResponse {
    pub items: Vec<AdminOrderDto>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct AdminTransactionDto {
    pub id: Uuid,
    pub order_id: Option<Uuid>,
    pub payment_system: PaymentSystem,
    pub external_tx_id: String,
    pub amount_received: f64,
    pub raw_request: serde_json::Value,
    pub created_at: String,
}

#[derive(Object, Debug, Serialize, Deserialize)]
pub struct PaginatedTransactionsResponse {
    pub items: Vec<AdminTransactionDto>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

pub struct AdminBillingApi {
    db: DatabaseConnection,
}

impl AdminBillingApi {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    async fn ensure_admin(&self, auth: &AdminToken) -> poem::Result<Uuid> {
        validate_admin_session(&self.db, &auth.0.token)
            .await
            .map_err(|err| poem::Error::from_string(err, StatusCode::UNAUTHORIZED))
    }
}

#[OpenApi]
impl AdminBillingApi {
    #[oai(path = "/admin/products", method = "get")]
    async fn list_products(&self, auth: AdminToken) -> poem::Result<Json<Vec<AdminProductDto>>> {
        self.ensure_admin(&auth).await?;

        let items = products::Entity::find()
            .order_by_asc(products::Column::SortOrder)
            .all(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(items.into_iter().map(AdminProductDto::from).collect()))
    }

    #[oai(path = "/admin/products", method = "post")]
    async fn create_product(
        &self,
        auth: AdminToken,
        req: Json<CreateProductRequest>,
    ) -> poem::Result<Json<AdminProductDto>> {
        self.ensure_admin(&auth).await?;

        let now = Utc::now();
        let new_prod = products::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(req.name.clone()),
            description: Set(req.description.clone()),
            price: Set(req.price),
            currency: Set(req.currency),
            product_type: Set(req.product_type),
            target_id: Set(req.target_id),
            sort_order: Set(req.sort_order.unwrap_or(0)),
            badge: Set(req.badge.clone()),
            metadata: Set(req.metadata.clone()),
            is_active: Set(req.is_active),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let inserted = new_prod
            .insert(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(AdminProductDto::from(inserted)))
    }

    #[oai(path = "/admin/products/:id", method = "patch")]
    async fn update_product(
        &self,
        auth: AdminToken,
        id: Path<Uuid>,
        req: Json<UpdateProductRequest>,
    ) -> poem::Result<Json<AdminProductDto>> {
        self.ensure_admin(&auth).await?;

        let prod = products::Entity::find_by_id(id.0)
            .one(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or_else(|| poem::Error::from_string("Product not found", StatusCode::NOT_FOUND))?;

        let mut active: products::ActiveModel = prod.into();
        if let Some(v) = &req.name {
            active.name = Set(v.clone());
        }
        if let Some(v) = &req.description {
            active.description = Set(v.clone());
        }
        if let Some(v) = req.price {
            active.price = Set(v);
        }
        if let Some(v) = req.currency {
            active.currency = Set(v);
        }
        if let Some(v) = req.product_type {
            active.product_type = Set(v);
        }
        if let Some(v) = req.target_id {
            active.target_id = Set(v);
        }
        if let Some(v) = req.sort_order {
            active.sort_order = Set(v);
        }
        if let Some(v) = &req.badge {
            active.badge = Set(v.clone());
        }
        if let Some(v) = &req.metadata {
            active.metadata = Set(v.clone());
        }
        if let Some(v) = req.is_active {
            active.is_active = Set(v);
        }
        active.updated_at = Set(Utc::now());

        let updated = active
            .update(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(AdminProductDto::from(updated)))
    }

    #[oai(path = "/admin/products/:id", method = "delete")]
    async fn delete_product(&self, auth: AdminToken, id: Path<Uuid>) -> poem::Result<Json<bool>> {
        self.ensure_admin(&auth).await?;

        products::Entity::delete_by_id(id.0)
            .exec(&self.db)
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;
        Ok(Json(true))
    }

    #[oai(path = "/admin/orders", method = "get")]
    async fn list_orders(
        &self,
        auth: AdminToken,
        page: Query<Option<u64>>,
        page_size: Query<Option<u64>>,
        status: Query<Option<OrderStatus>>,
    ) -> poem::Result<Json<PaginatedOrdersResponse>> {
        self.ensure_admin(&auth).await?;

        let page = page.0.unwrap_or(1);
        let page_size = page_size.0.unwrap_or(20);

        let mut query = orders::Entity::find();
        if let Some(st) = status.0 {
            query = query.filter(orders::Column::Status.eq(st));
        }

        let paginator = query
            .order_by_desc(orders::Column::CreatedAt)
            .paginate(&self.db, page_size);
        let total = paginator.num_items().await.unwrap_or(0);
        let items = paginator
            .fetch_page(page.saturating_sub(1))
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .into_iter()
            .map(|o| AdminOrderDto {
                id: o.id,
                user_id: o.user_id,
                product_id: o.product_id,
                amount: o.amount,
                currency: o.currency,
                status: o.status,
                is_gift: o.is_gift,
                metadata: o.metadata,
                created_at: o.created_at.to_rfc3339(),
                updated_at: o.updated_at.to_rfc3339(),
            })
            .collect();

        Ok(Json(PaginatedOrdersResponse {
            items,
            total,
            page,
            page_size,
        }))
    }

    #[oai(path = "/admin/transactions", method = "get")]
    async fn list_transactions(
        &self,
        auth: AdminToken,
        page: Query<Option<u64>>,
        page_size: Query<Option<u64>>,
    ) -> poem::Result<Json<PaginatedTransactionsResponse>> {
        self.ensure_admin(&auth).await?;

        let page = page.0.unwrap_or(1);
        let page_size = page_size.0.unwrap_or(20);

        let paginator = transactions::Entity::find()
            .order_by_desc(transactions::Column::CreatedAt)
            .paginate(&self.db, page_size);

        let total = paginator.num_items().await.unwrap_or(0);
        let items = paginator
            .fetch_page(page.saturating_sub(1))
            .await
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .into_iter()
            .map(|t| AdminTransactionDto {
                id: t.id,
                order_id: t.order_id,
                payment_system: t.payment_system,
                external_tx_id: t.external_tx_id,
                amount_received: t.amount_received,
                raw_request: t.raw_request,
                created_at: t.created_at.to_rfc3339(),
            })
            .collect();

        Ok(Json(PaginatedTransactionsResponse {
            items,
            total,
            page,
            page_size,
        }))
    }
}
