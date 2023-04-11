use crate::{
    internal_voter::InternalVoter,
    voting::{Election, Status},
};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct InternalElection {
    name: String,
    groups: HashSet<String>,
    votes: HashMap<String, u64>,
    voted: HashSet<String>,
    end_date: DateTime<Utc>,
}

impl InternalElection {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_qualified_group(&self, group: &str) -> bool {
        self.groups.contains(group)
    }

    #[allow(dead_code)]
    pub fn is_voted(&self, voter: &str) -> bool {
        self.voted.contains(voter)
    }

    #[allow(dead_code)]
    pub fn groups(&self) -> impl Iterator<Item = &String> {
        self.groups.iter()
    }

    #[allow(dead_code)]
    pub fn choices(&self) -> impl Iterator<Item = &String> {
        self.votes.keys()
    }

    #[allow(dead_code)]
    pub fn end_date(&self) -> DateTime<Utc> {
        self.end_date
    }

    #[tracing::instrument(skip_all)]
    pub fn vote(&mut self, voter: &InternalVoter, choice: &str) -> Result<(), VoteError> {
        if !self.is_qualified_group(voter.group()) {
            return Err(VoteError::GroupNotAllow);
        }
        if self.is_ended() {
            // Which error should return on casting to ended election???
            return Err(VoteError::InvalidElection);
        }
        let Some(vote_count) = self.votes.get_mut(choice) else {
            return Err(VoteError::InvalidElection);
        };

        if self.voted.insert(voter.name().to_owned()) {
            *vote_count += 1;
            info!(
                "A successful cast on {election_name}",
                election_name = self.name()
            );
            Ok(())
        } else {
            // Already casted if `.insert()` return false
            Err(VoteError::AlreadyCasted)
        }
    }

    #[tracing::instrument]
    pub fn results(&self) -> impl Iterator<Item = (&str, u64)> {
        self.votes.iter().map(|(k, v)| (k.as_str(), *v))
    }

    pub fn is_ended(&self) -> bool {
        self.end_date < Utc::now()
    }
}

impl TryFrom<Election> for InternalElection {
    type Error = InvalidElection;

    fn try_from(election: Election) -> Result<Self, Self::Error> {
        Ok(Self {
            name: election.name,
            groups: HashSet::from_iter(election.groups.into_iter()),
            votes: HashMap::from_iter(election.choices.into_iter().map(|choice| (choice, 0))),
            voted: HashSet::new(),
            end_date: Utc.from_utc_datetime(
                &NaiveDateTime::from_timestamp_opt(
                    election.end_date.seconds,
                    election.end_date.nanos as u32,
                )
                .ok_or(InvalidElection)?,
            ),
        })
    }
}

#[derive(Clone, Debug, Error)]
#[error("Invalid election")]
pub struct InvalidElection;

#[derive(Clone, Copy, Debug, Error)]
pub enum VoteError {
    #[error("Invalid authentication token")]
    InvalidAuth,
    #[error("Invalid election name")]
    InvalidElection,
    #[error("The voter's group is not allowed in the election")]
    GroupNotAllow,
    #[error("A previous vote has been cast")]
    AlreadyCasted,
}

impl From<VoteError> for Status {
    fn from(val: VoteError) -> Self {
        match val {
            VoteError::InvalidAuth => Status::CAST_VOTE_AUTH,
            VoteError::InvalidElection => Status::CAST_VOTE_INVALID,
            VoteError::GroupNotAllow => Status::CAST_VOTE_NOTALLOW,
            VoteError::AlreadyCasted => Status::CAST_VOTE_CASTED,
        }
    }
}
