use actix_web::{web, HttpResponse, Scope};
use validator::Validate;

use crate::{
    service::user_service::UserService,
    auth::{Authenticated, RequireAuth},
    dtos::dtos::{NameUpdateDto, RequestQueryDto, RoleUpdateDto, UserPasswordUpdateDto},
    error::HttpError, models::models::UserRole, AppState
};

// This fn define endpoints route and if the user is authenticated
pub fn users_handler() -> Scope {
    web::scope("/api/users")
        .route(
            "", 
            web::get()
            .to(get_users),
        )
        .route(
            "/me", 
            web::get().to(get_me).wrap(RequireAuth::allowed_roles(vec![
                UserRole::User,
                UserRole::Moderator,
                UserRole::Admin,
            ])),
        )
        .route(
            "/me/name",
            web::put().to(update_user_name).wrap(RequireAuth::allowed_roles(vec![
                UserRole::User,
                UserRole::Moderator,
                UserRole::Admin,
            ])) 
        )
        .route(
            "/me/role",
            web::put().to(update_user_role).wrap(RequireAuth::allowed_roles(vec![
                UserRole::User,
                UserRole::Moderator,
                UserRole::Admin,
            ])) 
        )
        .route(
            "/me/password", 
            web::put().to(update_user_password).wrap(RequireAuth::allowed_roles(vec![
                UserRole::User,
                UserRole::Moderator,
                UserRole::Admin,
            ]))
        )
}

#[utoipa::path(
    get,
    path = "/api/users/me",
    tag = "Get Authenticated User Endpoint",
    responses(
        (status = 200, description= "Authenticated User", body = UserResponseDto),
        (status= 500, description= "Internal Server Error", body = Response )
       
    ),
    security(
       ("token" = [])
   )
)]
pub async fn get_me(
    user: Authenticated, 
    app_state: web::Data<AppState>) -> Result<HttpResponse, HttpError> {
    
    let user_service = UserService::new(app_state);
    let response_data = user_service.get_me(user).await?;
    
    Ok(HttpResponse::Ok().json(response_data))
}


#[utoipa::path(
    get,
    path = "/api/users",
    tag = "Get All Users Endpoint",
    params(
        RequestQueryDto
    ),
    responses(
        (status = 200, description= "All Users", body = [UserResponseDto]),
        (status=401, description= "Authentication Error", body= Response),
        (status=403, description= "Permission Denied Error", body= Response),
        (status= 500, description= "Internal Server Error", body = Response )
       
    ),
    security(
       ("token" = [])
   )
)]
pub async fn get_users(
    query: web::Query<RequestQueryDto>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, HttpError> {
    let query_params: RequestQueryDto = query.into_inner();

    let user_service = UserService::new(app_state);
    let response_data = user_service.get_users(query_params).await?;
    
    Ok(HttpResponse::Ok().json(response_data))
}


#[utoipa::path(
    put,
    path = "/api/users/me/name",
    tag = "Update User Name Endpoint",
    request_body(content = NameUpdateDto, example = json!({"name": "john doe"})),
    responses(
        (status = 200, description = "User name updated successfully", body = UserResponseDto),
        (status = 400, description = "Invalid request data", body = Response),
        (status = 401, description = "Unauthorized", body = Response),
        (status = 403, description = "Forbidden", body = Response),
        (status = 500, description = "Internal server error", body = Response)
    ),
    security(
        ("token" = [])
    )
)]
pub async fn update_user_name(
    user: Authenticated,
    body: web::Json<NameUpdateDto>,
    app_state: web::Data<AppState>
) -> Result<HttpResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user_service = UserService::new(app_state);
    let response = user_service.update_user_name(user.id, &body.name).await?;
    
    Ok(HttpResponse::Ok().json(response))
}

#[utoipa::path(
    put,
    path = "/api/users/me/role",
    tag = "Update User Role Endpoint",
    request_body(content = RoleUpdateDto, example = json!({"role": "User"})),
    responses(
        (status = 200, description = "User role updated successfully", body = UserResponseDto),
        (status = 400, description = "Invalid request data", body = Response),
        (status = 401, description = "Unauthorized", body = Response),
        (status = 403, description = "Forbidden", body = Response),
        (status = 500, description = "Internal server error", body = Response)
    ),
    security(
        ("token" = [])
    )
)]
pub async fn update_user_role(
    user: Authenticated,
    body: web::Json<RoleUpdateDto>,
    app_state: web::Data<AppState>
) -> Result<HttpResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user_service = UserService::new(app_state);
    let response = user_service.update_user_role(user.id, body.role).await?;
    
    Ok(HttpResponse::Ok().json(response))
}

#[utoipa::path(
    put,
    path = "/api/users/me/password",
    tag = "Update User Password Endpoint",
    request_body(content = UserPasswordUpdateDto, example = json!({
        "new_password": "password1234",
        "new_password_confirm": "password1234",
        "old_password": "password123",
    })),
    responses(
        (status = 200, description = "Password updated successfully", body = Response),
        (status = 400, description = "Invalid request data", body = Response),
        (status = 401, description = "Unauthorized", body = Response),
        (status = 403, description = "Forbidden", body = Response),
        (status = 500, description = "Internal server error", body = Response)
    ),
    security(
        ("token" = [])
    )
)]
pub async fn update_user_password(
    user: Authenticated,
    body: web::Json<UserPasswordUpdateDto>,
    app_state: web::Data<AppState>
) -> Result<HttpResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

        let user_service = UserService::new(app_state);
        let response_data = user_service.update_user_password(user.id, body.old_password.clone(), body.new_password.clone()).await?;
    
        Ok(HttpResponse::Ok().json(response_data))
}