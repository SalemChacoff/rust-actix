use crate::auth::Authenticated;
use crate::models::models::UserRole;
use crate::repository::db::UserExt;
// user_service.rs
use crate::dtos::dtos::{
    FilterUserDto, RequestQueryDto, Response, UserData, UserListResponseDto,
    UserResponseDto,
};
use crate::error::HttpError;
use crate::utils::password;
use crate::AppState;
use actix_web::web;
use uuid::Uuid;
use validator::Validate;

pub struct UserService {
    app_state: web::Data<AppState>,
}

impl UserService {
    pub fn new(app_state: web::Data<AppState>) -> Self {
        UserService { app_state }
    }

    pub async fn get_me(&self, user: Authenticated) -> Result<UserResponseDto, HttpError> {
        let filtered_user = FilterUserDto::filter_user(&user);

        Ok(UserResponseDto {
            status: "success".to_string(),
            data: UserData {
                user: filtered_user,
            },
        })
    }

    pub async fn get_users(
        &self,
        query_params: RequestQueryDto,
    ) -> Result<UserListResponseDto, HttpError> {
        query_params
            .validate()
            .map_err(|e| HttpError::bad_request(e.to_string()))?;

        let page = query_params.page.unwrap_or(1);
        let limit = query_params.limit.unwrap_or(10);

        let users = self
            .app_state
            .db_client
            .get_users(page as u32, limit)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        let users_count = self
            .app_state
            .db_client
            .get_user_count()
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        Ok(UserListResponseDto {
            status: "success".to_string(),
            users: FilterUserDto::filter_users(&users),
            results: users_count,
        })
    }

    pub async fn update_user_name(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<UserResponseDto, HttpError> {
        let result = self
            .app_state
            .db_client
            .update_user_name(user_id, name)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        let filtered_user = FilterUserDto::filter_user(&result);

        Ok(UserResponseDto {
            status: "success".to_string(),
            data: UserData {
                user: filtered_user,
            },
        })
    }

    pub async fn update_user_role(
        &self,
        user_id: Uuid,
        role: UserRole,
    ) -> Result<UserResponseDto, HttpError> {
        let result = self
            .app_state
            .db_client
            .update_user_role(user_id, role)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        let filtered_user = FilterUserDto::filter_user(&result);

        Ok(UserResponseDto {
            status: "success".to_string(),
            data: UserData {
                user: filtered_user,
            },
        })
    }

    pub async fn update_user_password(
        &self,
        user_id: Uuid,
        old_password: String,
        new_password: String,
    ) -> Result<Response, HttpError> {
        let result = self
            .app_state
            .db_client
            .get_user(Some(user_id.clone()), None, None)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        let user = result.ok_or(HttpError::bad_request("Server error"))?;

        let password_match = password::compare(&old_password, &user.password)
            .map_err(|e| HttpError::bad_request(e.to_string()))?;

        if !password_match {
            return Err(HttpError::server_error(
                "Old password is incorrect".to_string(),
            ))?;
        }

        let hashed_password =
            password::hash(&new_password).map_err(|e| HttpError::server_error(e.to_string()))?;

        self.app_state
            .db_client
            .update_user_password(user_id.clone(), hashed_password)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        let response = Response {
            message: "Password updated successfully".to_string(),
            status: "success",
        };

        Ok(response)
    }
}
