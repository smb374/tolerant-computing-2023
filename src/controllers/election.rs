use crate::models::{InternalElection, InternalVoter, VoteError};
use couch_rs::{database::Database, error::CouchResult, types::find::FindQuery, Client};

#[derive(Clone, Debug)]
pub struct ElectionController {
    dbconn: Database,
}

impl ElectionController {
    pub const DATABASE_NAME: &str = "elections";

    pub async fn from_db_client(client: &Client) -> CouchResult<Self> {
        Ok(Self {
            dbconn: client.db(Self::DATABASE_NAME).await?,
        })
    }

    #[tracing::instrument]
    pub async fn find_election_by_name(&self, name: &str) -> CouchResult<Option<InternalElection>> {
        let query = FindQuery::new(json!({
            "name": name,
        }))
        .limit(1);

        Ok(self
            .dbconn
            .find::<InternalElection>(&query)
            .await?
            .rows
            .into_iter()
            .next())
    }

    pub async fn create(&self, election: &mut InternalElection) -> CouchResult<bool> {
        if self.find_election_by_name(election.name()).await?.is_some() {
            return Ok(false);
        }

        self.dbconn.create(election).await?;
        Ok(true)
    }

    pub async fn vote(
        &self,
        election: &mut InternalElection,
        voter: &InternalVoter,
        choice: &str,
    ) -> CouchResult<Result<(), VoteError>> {
        let result = election.vote(voter, choice);
        if result.is_ok() {
            self.dbconn.save(election).await?;
        }

        Ok(result)
    }
}
