use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use magic_wormhole::Wormhole;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    persistent::{PersistentKeyMaterial, PersistentState},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthChallenge {
    public_key_hex: String,
    nonce_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthProof {
    public_key_hex: String,
    signature_hex: String,
}

pub fn generate_identity() -> PersistentKeyMaterial {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    PersistentKeyMaterial {
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        secret_key_hex: hex::encode(signing_key.to_bytes()),
    }
}

pub async fn authenticate(wormhole: &mut Wormhole, state: &mut PersistentState) -> Result<()> {
    let signing_key = signing_key_from_hex(&state.local_identity.secret_key_hex)?;
    let local_public_key_hex = state.local_identity.public_key_hex.clone();
    let local_nonce = random_nonce();
    let local_challenge = AuthChallenge {
        public_key_hex: local_public_key_hex.clone(),
        nonce_hex: hex::encode(local_nonce),
    };

    wormhole.send_json(&local_challenge).await?;
    let peer_challenge: AuthChallenge = wormhole.receive_json().await??;
    let peer_key = verifying_key_from_hex(&peer_challenge.public_key_hex)?;
    let peer_public_key_hex = hex::encode(peer_key.to_bytes());

    if let Some(expected_peer) = &state.peer_public_key_hex
        && *expected_peer != peer_public_key_hex
    {
        return Err(Error::Authentication(format!(
            "persistent peer key mismatch: expected {}, got {}",
            expected_peer, peer_public_key_hex
        )));
    }

    let peer_nonce = hex::decode(&peer_challenge.nonce_hex)
        .map_err(|error| Error::Authentication(format!("invalid peer challenge nonce: {error}")))?;
    let signature = signing_key.sign(&peer_nonce);
    let local_proof = AuthProof {
        public_key_hex: local_public_key_hex,
        signature_hex: hex::encode(signature.to_bytes()),
    };

    wormhole.send_json(&local_proof).await?;
    let peer_proof: AuthProof = wormhole.receive_json().await??;

    if peer_proof.public_key_hex != peer_public_key_hex {
        return Err(Error::Authentication(
            "peer proof public key did not match the challenge identity".into(),
        ));
    }

    let peer_signature = signature_from_hex(&peer_proof.signature_hex)?;
    peer_key
        .verify(&local_nonce, &peer_signature)
        .map_err(|error| Error::Authentication(format!("invalid peer signature: {error}")))?;

    if state.peer_public_key_hex.is_none() {
        state.peer_public_key_hex = Some(peer_public_key_hex);
    }

    Ok(())
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn signing_key_from_hex(input: &str) -> Result<SigningKey> {
    let bytes = decode_fixed_hex::<32>(input, "signing key")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key_from_hex(input: &str) -> Result<VerifyingKey> {
    let bytes = decode_fixed_hex::<32>(input, "verifying key")?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| Error::Authentication(format!("invalid verifying key: {error}")))
}

fn signature_from_hex(input: &str) -> Result<Signature> {
    let bytes = decode_fixed_hex::<64>(input, "signature")?;
    Ok(Signature::from_bytes(&bytes))
}

fn decode_fixed_hex<const N: usize>(input: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(input)
        .map_err(|error| Error::Authentication(format!("invalid {label} hex: {error}")))?;
    let actual_len = bytes.len();
    bytes.try_into().map_err(|_| {
        Error::Authentication(format!(
            "{label} must be exactly {} bytes, got {}",
            N, actual_len
        ))
    })
}
