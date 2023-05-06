#[macro_use]
extern crate thiserror;
#[macro_use]
extern crate tracing;

use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ::config::{Environment, File as ConfigFile};
use clap::Parser;
use crate::args::ServerArgs;

use self::config::ServerConfig;
use couch_rs::Client as CouchClient;
use dashmap::{mapref::entry::Entry, DashMap};
use ed25519_dalek::{Signature, Verifier};
use tokio::time::MissedTickBehavior;
use tonic::{transport::Server, Request, Response};

use proto::{
    e_voting_server::{EVoting, EVotingServer},
    voter_registration_server::{VoterRegistration, VoterRegistrationServer},
    *,
};

mod args;
mod config;
mod models;
pub mod proto;
mod token_manager;

use models::{InternalElection, InternalVoter};
use token_manager::TokenManager;

type RPCResult<T> = Result<Response<T>, tonic::Status>;

#[derive(Debug, Default)]
struct VotingServer {
    // voters: A map that stores the voters that is registered.
    // key: Name of the voter.
    // value: Internal voter representation.
    voters: DashMap<String, InternalVoter>,
    elections: DashMap<String, InternalElection>,
    // tokens: See token_manager.rs
    tokens: TokenManager,
}

#[tonic::async_trait]
impl VoterRegistration for VotingServer {
    #[tracing::instrument(skip_all)]
    async fn register_voter(&self, req: Request<Voter>) -> RPCResult<Status> {
        let v = req.into_inner();

        match self.voters.entry(v.name.clone()) {
            Entry::Occupied(_) => Ok(Response::new(Status::REGISTER_VOTER_EXISTED)),
            Entry::Vacant(e) => {
                let Ok(ivoter) = InternalVoter::try_from(v) else {
                    info!("Malformed public key");
                    return Ok(Response::new(Status::REGISTER_VOTER_UNKNOWN));
                };
                e.insert(ivoter);

                Ok(Response::new(Status::REGISTER_VOTER_SUCCESS))
            }
        }
    }

    #[tracing::instrument(skip_all)]
    async fn unregister_voter(&self, req: Request<VoterName>) -> RPCResult<Status> {
        let n = req.into_inner();

        if self.voters.remove(&n.name).is_some() {
            Ok(Response::new(Status::UNREGISTER_VOTER_SUCCESS))
        } else {
            Ok(Response::new(Status::UNREGISTER_VOTER_NOTFOUND))
        }
    }
}

#[tonic::async_trait]
impl EVoting for VotingServer {
    /// PreAuth stage for challenge-response protocol.
    ///
    /// It will return a challenge that is 128 bytes long.
    ///
    /// The function will return a challenge with 0s when the user request a challenge-response is
    /// not registered before, as the spec nor the protocol definition specify the error handling.
    #[tracing::instrument(skip_all)]
    async fn pre_auth(&self, req: Request<VoterName>) -> RPCResult<Challenge> {
        let n = req.into_inner();
        if let Some(v) = self.voters.get_mut(&n.name).as_mut() {
            Ok(Response::new(Challenge {
                value: Vec::from(v.generate_challenge().as_slice()),
            }))
        } else {
            Ok(Response::new(Challenge {
                value: vec![0; 128],
            }))
        }
    }
    /// Auth stage for challenge-response protocol.
    ///
    /// The function will receive a user's response from previous challenge, which is a signature
    /// of the challenge. If the signature can be successfully verified against the publickey that
    /// the user provided when registering, the function will return a token that is 128 bytes long
    /// as the auth token.
    ///
    /// The function will also renew the auth token if the user who completes the
    /// challenge-response has a valid token that is not expired. The old token will be expired as
    /// a new token is generated.
    ///
    /// Same as pre_auth, since there's no error handling spec, the function will return a token
    /// with 0s to show an error occurred, including: No Such User, Invalid Signature, Signature
    /// Verification failed.
    #[tracing::instrument(skip_all)]
    async fn auth(&self, req: Request<AuthRequest>) -> RPCResult<AuthToken> {
        let auth_req = req.into_inner();
        let name = &auth_req.name.name;
        let err_resp = Ok(Response::new(AuthToken {
            value: vec![0; 128],
        }));

        let Some(mut voter_entry) = self.voters.get_mut(name) else {
            info!("No such voter or challenge.");
            return err_resp;
        };
        let (Ok(sig), Some(msg)) = (
            Signature::from_bytes(&auth_req.response.value),
            voter_entry.take_challenge(),
        ) else {
            warn!("Invalid Signature.");
            return err_resp;
        };
        let pubk = voter_entry.public_key();

        match pubk.verify(&msg, &sig) {
            Ok(()) => {
                info!(
                    "Successful authentication of {voter}",
                    voter = voter_entry.name(),
                );
                Ok(Response::new(AuthToken {
                    value: Vec::from(self.tokens.generate_token(voter_entry.name())),
                }))
            }
            Err(e) => {
                error!(
                    "Challenge-Response failed for {voter}: {error}",
                    voter = voter_entry.name(),
                    error = e
                );
                err_resp
            }
        }
    }

    #[tracing::instrument(skip_all)]
    async fn create_election(&self, req: Request<Election>) -> RPCResult<Status> {
        let election = req.into_inner();

        let Some(token) = self.tokens.lookup_token(&election.token.value) else {
            return Ok(Response::new(Status::CREATE_ELECTION_AUTH));
        };
        let Some(_voter_entry) = self.voters.get(token.voter_name()) else {
            return Ok(Response::new(Status::CREATE_ELECTION_AUTH));
        };

        if election.choices.is_empty() || election.groups.is_empty() {
            return Ok(Response::new(Status::CREATE_ELECTION_INVALID));
        }

        let Ok(internal_election) = InternalElection::try_from(election) else {
            return Ok(Response::new(Status::CREATE_ELECTION_UNKNOWN));
        };

        match self.elections.entry(internal_election.name().to_owned()) {
            Entry::Occupied(_) => return Ok(Response::new(Status::CREATE_ELECTION_UNKNOWN)),
            Entry::Vacant(e) => {
                let entry = e.insert(internal_election);
                info!("Created election: {election:?}", election = entry.value());
            }
        };

        return Ok(Response::new(Status::CREATE_ELECTION_SUCCESS));
    }

    #[tracing::instrument(skip_all)]
    async fn cast_vote(&self, req: Request<Vote>) -> RPCResult<Status> {
        let vote_req = req.into_inner();

        let Some(token) = self.tokens.lookup_token(&vote_req.token.value) else {
            return Ok(Response::new(Status::CAST_VOTE_AUTH));
        };
        let Some(voter_entry) = self.voters.get(token.voter_name()) else {
            return Ok(Response::new(Status::CAST_VOTE_AUTH));
        };
        let Some(mut election_entry) = self.elections.get_mut(&vote_req.election_name) else {
            return Ok(Response::new(Status::CAST_VOTE_INVALID));
        };

        if let Err(e) = election_entry
            .value_mut()
            .vote(voter_entry.value(), &vote_req.choice_name)
        {
            Ok(Response::new(e.into()))
        } else {
            Ok(Response::new(Status::CAST_VOTE_SUCCESS))
        }
    }

    #[tracing::instrument(skip_all)]
    async fn get_result(&self, req: Request<ElectionName>) -> RPCResult<ElectionResult> {
        let election_name = req.into_inner().name;

        let Some(election_entry) = self.elections.get(&election_name) else {
            return Ok(Response::new(ElectionResult::ELECTION_RESULT_NOTFOUND));
        };
        if !election_entry.value().is_ended() {
            return Ok(Response::new(ElectionResult::ELECTION_RESULT_ONGOING));
        }

        let vote_counts: Vec<VoteCount> = election_entry
            .results()
            .map(|(choice, count)| VoteCount {
                choice_name: choice.to_owned(),
                count: count as i32,
            })
            .collect();

        Ok(Response::new(ElectionResult {
            status: 0,
            counts: vote_counts,
        }))
    }
}

async fn cronjob_clean_token(server: Arc<VotingServer>) {
    let mut interval = tokio::time::interval(Duration::from_secs(600));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Consume the first immediate tick.
    interval.tick().await;

    loop {
        interval.tick().await;
        info!("Cleaning expired tokens");
        server.tokens.clean_expired_token();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    let args = ServerArgs::parse();

    let mut cfg: ServerConfig = ::config::Config::builder()
        .add_source(ConfigFile::with_name(&args.config).required(false))
        .add_source(Environment::with_prefix("VOTING").separator("."))
        .build()?
        .try_deserialize()?;
    cfg.merge_from_args(&args);

    info!("Configuration loaded");

    debug!("Trying to connect to database: {}", &cfg.database.uri);
    let mut client = CouchClient::new_with_timeout(
        &cfg.database.uri,
        cfg.database.username.as_deref(),
        cfg.database.password.as_deref(),
        cfg.database.timeout,
    )?;
    client.set_prefix(cfg.database.prefix.clone());

    let dbstatus = client.check_status().await?;
    info!("Connected to database: {:?}", &dbstatus);

    let addr = SocketAddr::from((cfg.host, cfg.port));
    let voting = Arc::new(VotingServer::default());
    tokio::spawn(cronjob_clean_token(voting.clone()));

    info!("Starting server listening on {addr}");
    Server::builder()
        .add_service(VoterRegistrationServer::from_arc(Arc::clone(&voting)))
        .add_service(EVotingServer::from_arc(Arc::clone(&voting)))
        .serve(addr)
        .await?;
    Ok(())
}
