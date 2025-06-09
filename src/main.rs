use actix_cors::Cors;
use actix_web::{
    App, HttpResponse, HttpServer, Responder, error::ErrorUnauthorized, get, post, web,
};
use dotenv::dotenv;
use jwt::{Claims, generate_jwt, validate_jwt};
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use std::env;
use yahoo::fetch_stock_quotes;

mod jwt;
mod yahoo;

#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthResponse {
    token: String,
}

#[post("/auth/login")]
async fn login(req_body: web::Json<AuthRequest>) -> impl Responder {
    dotenv().ok();
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set in env.");
    // some basic auth, username/password must match what is in .env file.
    let username = env::var("USER_NAME").expect("USER_NAME must be set in env.");
    let password = env::var("USER_PASSWORD").expect("USER_PASSWORD must be set in env.");
    if username == req_body.username && password == req_body.password {
        let permissions = vec![String::from("read")];
        let token = generate_jwt(&username, permissions, jwt_secret.as_bytes())
            .expect("Failed to generate JWT.");
        return HttpResponse::Ok().json(AuthResponse { token });
    }
    HttpResponse::Unauthorized().body("Invalid credentials.")
}

struct AuthenticatedUser {
    claims: Claims,
}

impl actix_web::FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;
    fn from_request(
        req: &actix_web::HttpRequest,
        payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        dotenv().ok();
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set.");

        let auth_header = req.headers().get("Authorization");
        if let Some(header_value) = auth_header {
            if let Ok(header_str) = header_value.to_str() {
                if let Some(token) = header_str.strip_prefix("Bearer ") {
                    match validate_jwt(token, jwt_secret.as_bytes()) {
                        Ok(claims) => {
                            return futures::future::ok(AuthenticatedUser { claims });
                        }
                        Err(e) => {
                            eprintln!("JWT validation failed {:?}.", e);
                            return futures::future::err(actix_web::error::ErrorUnauthorized(
                                "Invalid token.",
                            ));
                        }
                    }
                }
            }
        }
        futures::future::err(actix_web::error::ErrorUnauthorized(
            "Authorization header missing.",
        ))
    }
}

#[get("/api/stock-quotes")]
async fn get_stock_quotes(user: AuthenticatedUser) -> impl Responder {
    println!("Accessed by user: {}", user.claims.sub);
    println!("Permissions {:?}", user.claims.permissions);

    if !user.claims.permissions.contains(&"read".to_string()) {
        return HttpResponse::Forbidden().body("Insufficient permissions.");
    }

    let symbol = "NVDA";

    match fetch_stock_quotes(symbol).await {
        Ok(quotes) => {
            if let Ok(last_quote) = quotes.last_quote() {
                match to_string(&last_quote) {
                    Ok(json_string) => HttpResponse::Ok()
                        .content_type("application/json")
                        .body(json_string),
                    Err(e) => {
                        eprintln!("Error serializing quote to JSON: {:?}", e);
                        HttpResponse::InternalServerError().body("Failed to serialize quote data.")
                    }
                }
            } else {
                HttpResponse::NotFound().body(format!("No quotes found for {}", symbol))
            }
        }
        Err(e) => {
            eprintln!(
                "Error while retrieving stock quotes for {}: {:?}",
                symbol, e
            );
            HttpResponse::InternalServerError()
                .body("Internal error while retrieving stock quotes.")
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let port = env::var("PORT").unwrap_or_else(|_| String::from("8080"));
    let bind_address = format!("127.0.0.1:{}", port);

    println!("Starting server at {}", bind_address);

    HttpServer::new(|| {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec!["Content-Type", "Authorization"])
            .max_age(3600);
        App::new()
            .wrap(cors)
            .service(login)
            .service(get_stock_quotes)
    })
    .bind(&bind_address)?
    .run()
    .await
}
