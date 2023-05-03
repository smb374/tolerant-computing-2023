use base64::{prelude::BASE64_STANDARD, Engine};
use dashmap::DashMap;
use ed25519_dalek::{Digest, Sha512};

use crate::models::{VoterToken, AuthToken};

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

    #[tracing::instrument]
    pub fn clean_expired_token(&self) {
        self.inner.retain(|_k, v| !v.is_expired());
    }
}
