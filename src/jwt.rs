use chrono::{Duration, Utc};
use jsonwebtoken::{self, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub permissions: Vec<String>,
}

pub fn generate_jwt(
    user_id: &str,
    permissions: Vec<String>,
    secret: &[u8],
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expiration = now + Duration::hours(24); // high value for testing purposes

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration.timestamp(),
        iat: now.timestamp(),
        permissions,
    };

    let header = Header::default();
    encode(&header, &claims, &EncodingKey::from_secret(secret))
}

pub fn validate_jwt(token: &str, secret: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::default();
    decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation).map(|data| data.claims)
}
