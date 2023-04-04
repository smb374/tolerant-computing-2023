use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use ed25519_dalek::{Digest, Sha512};
use rand_core::{OsRng, RngCore};

pub type AuthToken = [u8; 128];

#[derive(Debug, Default)]
pub struct TokenManager {
    inner: DashMap<String, VoterToken>,
}

impl TokenManager {
    pub fn generate_token(&self, voter_name: &str) -> AuthToken {
        let (token, auth_token) = VoterToken::generate(voter_name);
        self.inner.insert(token.digest().to_owned(), token);

        auth_token
    }

    pub fn lookup_token(&self, auth_token: &[u8]) -> Option<VoterToken> {
        let dgst = Sha512::digest(auth_token);
        let digest = BASE64_STANDARD.encode(dgst.as_slice());

        self.inner.remove_if(&digest, |_, token| token.is_expired());
        self.inner.get(&digest).as_deref().cloned()
    }

    pub fn clean_expired_token(&self) {
        self.inner.retain(|_k, v| !v.is_expired());
    }
}

#[derive(Clone, Debug)]
pub struct VoterToken {
    digest: String,
    voter: String,
    expire: DateTime<Utc>,
}

impl VoterToken {
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
