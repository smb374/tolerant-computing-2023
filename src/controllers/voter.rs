use crate::models::InternalVoter;
use couch_rs::{
    database::Database, document::TypedCouchDocument, error::CouchResult, types::find::FindQuery,
    Client,
};
use dashmap::DashMap;
use ed25519_dalek::{Signature, Verifier};
use rand_core::{OsRng, RngCore};

pub type AuthChallenge = [u8; 128];

#[derive(Clone, Debug)]
pub struct VoterController {
    dbconn: Database,
    challenges: DashMap<String, AuthChallenge>,
}

impl VoterController {
    pub const DATABASE_NAME: &str = "voters";

    pub async fn from_db_client(client: &Client) -> CouchResult<Self> {
        Ok(Self {
            dbconn: client.db(Self::DATABASE_NAME).await?,
            challenges: DashMap::default(),
        })
    }

    #[tracing::instrument]
    pub async fn auth(&self, name: &str, sig: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let Some(voter) = self.find_user_by_name(name).await? else {
            info!("No such voter or challenge.");
            return Ok(false);
        };
        let (Ok(sig), Some(chal)) = (
            Signature::from_bytes(sig),
            self.take_challenge(&voter),
        ) else {
            warn!("Invalid Signature.");
            return Ok(false);
        };
        let pubk = voter.public_key();

        Ok(pubk.verify(&chal, &sig).map(|_| true)?)
    }

    #[tracing::instrument]
    pub async fn find_user_by_name(&self, name: &str) -> CouchResult<Option<InternalVoter>> {
        let query = FindQuery::new(json!({
            "name": name,
        }))
        .limit(1);

        Ok(self
            .dbconn
            .find::<InternalVoter>(&query)
            .await?
            .rows
            .into_iter()
            .next())
    }

    #[tracing::instrument]
    pub fn generate_challenge(&self, voter: &InternalVoter) -> AuthChallenge {
        let mut chal: AuthChallenge = [0; 128];
        OsRng.fill_bytes(&mut chal);
        self.challenges
            .insert(voter.get_id().into_owned(), chal);

        chal
    }

    #[tracing::instrument]
    pub fn take_challenge(&self, voter: &InternalVoter) -> Option<AuthChallenge> {
        self.challenges
            .remove(voter.get_id().as_ref())
            .map(|(_, chal)| chal)
    }

    #[tracing::instrument]
    pub async fn register(&self, voter: &mut InternalVoter) -> CouchResult<bool> {
        if self.find_user_by_name(voter.name()).await?.is_some() {
            return Ok(false);
        }

        self.dbconn.create(voter).await?;
        Ok(true)
    }

    #[tracing::instrument]
    pub async fn unregister(&self, name: &str) -> CouchResult<bool> {
        let query = FindQuery::new(json!({
            "name": name,
        }))
        .limit(1);

        let docs = self.dbconn.find::<InternalVoter>(&query).await?;
        let Some(voter) = docs.rows.into_iter().next() else {
            return Ok(false);
        };

        Ok(self.dbconn.remove(&voter).await)
    }
}
