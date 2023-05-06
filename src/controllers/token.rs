use crate::models::{AuthToken, DeleteDocument, VoterToken};
use base64::{prelude::BASE64_STANDARD, Engine};
use couch_rs::{database::Database, error::CouchResult, types::find::FindQuery, Client};
use ed25519_dalek::{Digest, Sha512};

#[derive(Clone, Debug)]
pub struct TokenController {
    dbconn: Database,
}

impl TokenController {
    pub const DATABASE_NAME: &str = "tokens";

    pub async fn from_db_client(client: &Client) -> CouchResult<Self> {
        Ok(Self {
            dbconn: client.db(Self::DATABASE_NAME).await?,
        })
    }

    #[tracing::instrument]
    pub async fn generate_token(&self, voter_name: &str) -> CouchResult<AuthToken> {
        let (mut token, auth_token) = VoterToken::generate(voter_name);
        self.dbconn.create(&mut token).await?;

        Ok(auth_token)
    }

    #[tracing::instrument]
    pub async fn lookup_token(&self, auth_token: &[u8]) -> Option<VoterToken> {
        let dgst = Sha512::digest(auth_token);
        let digest = BASE64_STANDARD.encode(dgst.as_slice());

        let query = FindQuery::new(json!({
            "digest": digest,
        }))
        .limit(1);

        let docs = self.dbconn.find::<VoterToken>(&query).await.ok()?;
        let token = docs.rows.into_iter().next()?;

        if token.is_expired() {
            self.dbconn.remove(&token).await;
            None
        } else {
            Some(token)
        }
    }

    #[tracing::instrument]
    pub async fn clean_expired_token(&self) -> CouchResult<()> {
        let docs = self
            .dbconn
            .find::<VoterToken>(&FindQuery::find_all())
            .await?;

        let mut deleting_docs = Vec::new();
        for token in docs.rows {
            if token.is_expired() {
                deleting_docs.push(DeleteDocument::from_doc(&token));
            }
        }

        self.dbconn.bulk_docs(&mut deleting_docs).await?;
        Ok(())
    }
}
