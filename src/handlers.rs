use actix_web::*;
use actix_multipart::{form::{MultipartForm, tempfile}};

use pgp::types::*;

use crate::{AppState, Nonce};
use crate::parsers;

#[derive(Debug,MultipartForm)]
pub struct VerifyPayload {
    #[multipart(limit="1M")]
    key: tempfile::TempFile,
    #[multipart(limit="1M")]
    signed: tempfile::TempFile,
}

pub async fn verify(MultipartForm(payload): MultipartForm::<VerifyPayload>, state: web::Data<AppState>) -> impl Responder {
    let pub_key = if let Ok(key) = parsers::parse_key(&payload.key).await {
        key
    } else {
        return HttpResponse::BadRequest().body("Key provided is not a signed public key");
    };

    let fingerprint = pub_key.fingerprint();
    let mut nonce_tracker = state.nonce_tracker.lock().await;
    let nonce = if let Some(nonce) = nonce_tracker.get_mut(&fingerprint) {
        // This is already technically captured by always creating nonces invalid, but it's better to program defensively :)
        nonce
    } else {
        return HttpResponse::BadRequest().body("No nonce set")
    };

    if !nonce.valid {
        return HttpResponse::BadRequest().body("Nonce re-use")
    }

    let signed_file = if let Ok(file) = parsers::parse_signed(&payload.signed).await {
        file
    } else {
        return HttpResponse::BadRequest().body("Signed data provided is not a signed file");
    };

    if let Ok(_) = signed_file.verify(&pub_key) {
        let payload = signed_file.get_content()
            .expect("Expected to be able to get message content")
            .expect("Expected message to not be empty");

        let payload = String::from_utf8(payload).expect("Expected signed message to be a valid utf_8 encoding of the u128 nonce");

        if payload == format!("{}", nonce.value) {
            // We only want to invalidate if we have verified the user's identity because
            // otherwise an attacker who knows the public key can hit /verify
            // in a tight loop and repeatedly invalidate the nonce.
            // We'd prefer only the valid key holder to be able to invalidate the nonce
            nonce.invalidate();
            return HttpResponse::Ok().body(format!("You are indeed {:?}", &fingerprint))
        }
        HttpResponse::BadRequest().body("Incorrect nonce! Potential replay attack detected")
    } else  {
        HttpResponse::BadRequest().body("That key was not used to sign this file")
    }
}

#[derive(Debug,MultipartForm)]
pub struct NoncePayload {
    #[multipart(limit="1M")]
    key: tempfile::TempFile,

}
pub async fn nonce(MultipartForm(payload): MultipartForm::<NoncePayload>, state: web::Data<AppState>) -> impl Responder {
    let pub_key = if let Ok(key) = parsers::parse_key(&payload.key).await {
        key
    } else {
        return HttpResponse::BadRequest().body("Key provided is not a signed public key");
    };

    let fingerprint = pub_key.fingerprint();
    let mut nonce_tracker = state.nonce_tracker.lock().await;
    let nonce = nonce_tracker.entry(fingerprint);
    let nonce = nonce.or_insert(Nonce::new());
    // Only invalide the nonce if it's been used to protect against DoS attacks
    // if /nonce always invalidated and gave a new nonce then an attacker could hit it in a tight loop
    // and disallow the key holder from ever hitting /nonce + /verify faster than the attacker can hit /nonce
    if !nonce.valid {
        nonce.up();
        nonce.validate();
    }

    HttpResponse::Ok().body(format!("{}", nonce.value))
}
