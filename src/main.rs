use actix_web::{App, HttpResponse, HttpServer, Responder, post, web};
use dotenv::dotenv;
use jwt::generate_jwt;
use serde::{Deserialize, Serialize};
use std::env;

mod jwt;

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let port = env::var("PORT").unwrap_or_else(|_| String::from("8080"));
    let bind_address = format!("127.0.0.1:{}", port);

    println!("Starting server at {}", bind_address);

    HttpServer::new(|| App::new().service(login))
        .bind(&bind_address)?
        .run()
        .await
}
