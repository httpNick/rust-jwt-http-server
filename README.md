# Rust JWT HTTP Server

A practice project to understand how to handle JWT tokens and implemented in Rust.

The plan for this server is to serve requests to clients that auth using the `/login` route, return a JWT which is then used in subsequent requests to retrieve data only available if the user holds a valid JWT validated by the server.


## .env file

A .env file is required to use this http server.

Example .env file:

```
JWT_SECRET=somejwtsecret
USER_NAME=user
USER_PASSWORD=password
```
