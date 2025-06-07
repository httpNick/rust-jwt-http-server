use chrono::{Duration, Utc};
use jsonwebtoken::{self, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_is_generated() {
        let permissions = vec![String::from("read")];
        let test_secret = [u8::MAX, u8::MIN];
        let test_jwt_reuslt = generate_jwt("test-user", permissions, &test_secret);
        assert!(test_jwt_reuslt.is_ok());
    }

    #[test]
    fn jwt_validate_fails_with_diff_secret() {
        let permissions = vec![String::from("read")];
        let test_secret = [u8::MAX, u8::MIN];
        let bad_test_secret = [1, 2, 3, 4];
        let jwt = generate_jwt("test-user", permissions, &test_secret);
        let validate_result = validate_jwt(&jwt.unwrap(), &bad_test_secret);
        assert!(validate_result.is_err());
    }
}
