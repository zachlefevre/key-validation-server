use actix_web::*;
use tokio::sync;

use pgp::types::*;

use std::collections;

mod parsers;
mod handlers;

/*
Failure Cases:
- MiTM
  An attacker who controls the network could wait for a user to send a valid /verify request
  *block* the request from making it to the applicatoin server
  and make an identical request to the application server.

- Nonce overflow. The nonce will _eventually_ overflow back to 0.
  Any attacker will be able to re-use any payload from when the nonce was naturally 0.
  solutions -- use something with a _huge_ value space, like UUIDs
            -- use a time-stamp based nonce, which would require time synchronization between client and server

-- DoS, although some subtle attacks were mitigated and documented in the code.

*/


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = std::net::TcpListener::bind("127.0.0.1:8888")?;

    let state = web::Data::new(AppState::new());

    let server = HttpServer::new(move || App::new()
                                 .app_data(state.clone())
                                 .route("/nonce", web::post().to(handlers::nonce))
                                 .route("/verify", web::post().to(handlers::verify))
);

    server
        .listen(listener)?
        .run()
        .await?;

    Ok(())

}

#[derive(Debug)]
struct Nonce { value: i128, valid: bool }
impl Nonce {
    fn new() -> Self {
        Self {
            value: 0,
            valid: false,
        }
    }
    fn invalidate(&mut self) {
        self.valid = false
    }
    fn validate(&mut self) {
        self.valid = true
    }
    fn up(&mut self) {
        self.value += 1
    }
}

#[derive(Debug)]
struct AppState {
    nonce_tracker: sync::Mutex<collections::HashMap<Fingerprint, Nonce>>
}
impl AppState {
    fn new() -> Self {
        Self {
            nonce_tracker: sync::Mutex::new(collections::HashMap::<Fingerprint, Nonce>::new())
        }
    }
}
