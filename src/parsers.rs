use pgp::{Deserializable, Message, SignedPublicKey};
use actix_multipart::form::tempfile;
use tokio::fs::File;
use tokio::io::{AsyncReadExt};

pub async fn parse_signed(payload: &tempfile::TempFile) -> anyhow::Result<Message> {
    let mut file = File::open(payload.file.path()).await?;

    let mut bytes: Vec<u8> = Vec::new();
    file.read_to_end(&mut bytes).await?;

    Ok(Message::from_bytes(&bytes[..])?)
}


pub async fn parse_key(payload: &tempfile::TempFile) -> anyhow::Result<SignedPublicKey> {
    let mut file = File::open(payload.file.path()).await?;

    let mut bytes: Vec<u8> = Vec::new();
    file.read_to_end(&mut bytes).await?;

    Ok(SignedPublicKey::from_bytes(&bytes[..])?)
}
