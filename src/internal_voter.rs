use crate::voting::Voter;
use ed25519_dalek::{PublicKey, SignatureError};
use rand_core::{OsRng, RngCore};

/// Internal voter representation.
///
/// name: Voter name.
/// group: Voter group.
/// public_key: Ed25519 public key for authentication.
/// challenge: temporary challenge store for verifying response.
/// token: Sha512 of the auth token in base64.
#[derive(Debug)]
pub struct InternalVoter {
    name: String,
    group: String,
    public_key: PublicKey,
    challenge: Option<[u8; 128]>,
}

impl TryFrom<Voter> for InternalVoter {
    type Error = SignatureError;
    fn try_from(value: Voter) -> Result<Self, Self::Error> {
        let public_key = PublicKey::from_bytes(&value.public_key)?;
        Ok(Self {
            name: value.name,
            group: value.group,
            public_key,
            challenge: None,
        })
    }
}

impl InternalVoter {
    #[tracing::instrument]
    pub fn generate_challenge(&mut self) -> &[u8; 128] {
        let mut buf: [u8; 128] = [0; 128];
        OsRng.fill_bytes(&mut buf);
        self.challenge.replace(buf);
        self.challenge.as_ref().unwrap()
    }

    pub fn take_challenge(&mut self) -> Option<[u8; 128]> {
        self.challenge.take()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn group(&self) -> &str {
        &self.group
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
}
