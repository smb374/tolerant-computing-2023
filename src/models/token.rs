use base64::prelude::*;
use chrono::{DateTime, Utc, Duration};
use ed25519_dalek::{Sha512, Digest};
use rand_core::{OsRng, RngCore};

pub type AuthToken = [u8; 128];

#[derive(Clone, Debug)]
pub struct VoterToken {
    digest: String,
    voter: String,
    expire: DateTime<Utc>,
}

impl VoterToken {
    #[tracing::instrument]
    pub fn generate(voter_name: &str) -> (Self, AuthToken) {
        let mut auth_token = [0u8; 128];
        OsRng.fill_bytes(&mut auth_token);
        let dgst = Sha512::digest(&auth_token);
        let digest = BASE64_STANDARD.encode(dgst.as_slice());

        (
            Self {
                digest,
                voter: voter_name.to_owned(),
                expire: Utc::now() + Duration::hours(1),
            },
            auth_token,
        )
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn voter_name(&self) -> &str {
        &self.voter
    }

    #[allow(dead_code)]
    pub fn expire(&self) -> DateTime<Utc> {
        self.expire
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expire
    }
}
