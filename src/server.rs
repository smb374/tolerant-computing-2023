#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_with;
#[macro_use]
extern crate thiserror;
#[macro_use]
extern crate tracing;

use self::config::ServerConfig;
use crate::args::ServerArgs;
use ::config::{Environment, File as ConfigFile};
use clap::Parser;
use couch_rs::Client as CouchClient;
use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::MissedTickBehavior;
use tonic::{transport::Server, Request, Response};

mod args;
mod config;
mod controllers;
mod models;
pub mod proto;

use controllers::{ElectionController, TokenController, VoterController};
use models::{InternalElection, InternalVoter};
use proto::{
    e_voting_server::{EVoting, EVotingServer},
    voter_registration_server::{VoterRegistration, VoterRegistrationServer},
    *,
};

type RPCResult<T> = Result<Response<T>, tonic::Status>;

#[derive(Clone, Debug)]
struct VotingServer {
    dbconn: CouchClient,
    // // voters: A map that stores the voters that is registered.
    // // key: Name of the voter.
    // // value: Internal voter representation.
    // voters: DashMap<String, InternalVoter>,
    // elections: DashMap<String, InternalElection>,
    // // tokens: See token_manager.rs
    elections: ElectionController,
    voters: VoterController,
    tokens: TokenController,
}

#[tonic::async_trait]
impl VoterRegistration for VotingServer {
    #[tracing::instrument(skip_all)]
    async fn register_voter(&self, req: Request<Voter>) -> RPCResult<Status> {
        let v = req.into_inner();

        let Ok(mut ivoter) = InternalVoter::try_from(v) else {
            info!("Malformed public key");
            return Ok(Response::new(Status::REGISTER_VOTER_UNKNOWN));
        };

        match self.voters.register(&mut ivoter).await {
            Ok(true) => Ok(Response::new(Status::REGISTER_VOTER_SUCCESS)),
            Ok(false) => Ok(Response::new(Status::REGISTER_VOTER_EXISTED)),
            Err(_) => Ok(Response::new(Status::REGISTER_VOTER_UNKNOWN)),
        }
    }

    #[tracing::instrument(skip_all)]
    async fn unregister_voter(&self, req: Request<VoterName>) -> RPCResult<Status> {
        let n = req.into_inner();

        match self.voters.unregister(&n.name).await {
            Ok(true) => Ok(Response::new(Status::UNREGISTER_VOTER_SUCCESS)),
            Ok(false) => Ok(Response::new(Status::UNREGISTER_VOTER_NOTFOUND)),
            Err(_) => Ok(Response::new(Status::UNREGISTER_VOTER_UNKNOWN)),
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
        match self.voters.find_user_by_name(&n.name).await {
            Ok(Some(voter)) => {
                let chal = self.voters.generate_challenge(&voter);

                Ok(Response::new(Challenge {
                    value: Vec::from(chal.as_slice()),
                }))
            }
            // Error occurred or user not found
            _ => Ok(Response::new(Challenge {
                value: vec![0; 128],
            })),
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
        let err_resp = Response::new(AuthToken {
            value: vec![0; 128],
        });
        let name = &auth_req.name.name;
        let chal = auth_req.response.value.as_slice();

        let auth_result = match self.voters.auth(name, chal).await {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Challenge-Response failed for {voter}: {error}",
                    voter = name,
                    error = e
                );
                return Ok(err_resp);
            }
        };

        if auth_result {
            info!("Successful authentication of {voter}", voter = name);
            if let Ok(token) = self.tokens.generate_token(name).await {
                Ok(Response::new(AuthToken {
                    value: token.to_vec(),
                }))
            } else {
                Ok(err_resp)
            }
        } else {
            Ok(err_resp)
        }
    }

    #[tracing::instrument(skip_all)]
    async fn create_election(&self, req: Request<Election>) -> RPCResult<Status> {
        let election_req = req.into_inner();

        let Some(token) = self.tokens.lookup_token(&election_req.token.value).await else {
            return Ok(Response::new(Status::CREATE_ELECTION_AUTH));
        };
        let Ok(Some(_voter)) = self.voters.find_user_by_name(token.voter_name()).await else {
            return Ok(Response::new(Status::CREATE_ELECTION_AUTH));
        };
        if election_req.choices.is_empty() || election_req.groups.is_empty() {
            return Ok(Response::new(Status::CREATE_ELECTION_INVALID));
        }
        let Ok(mut election) = InternalElection::try_from(election_req) else {
            return Ok(Response::new(Status::CREATE_ELECTION_UNKNOWN));
        };

        match self.elections.create(&mut election).await {
            Ok(true) => {
                info!("Created election: {election:?}", election = &election);
                Ok(Response::new(Status::CREATE_ELECTION_SUCCESS))
            }
            Ok(false) => Ok(Response::new(Status::CREATE_ELECTION_UNKNOWN)),
            Err(_) => Ok(Response::new(Status::CREATE_ELECTION_UNKNOWN)),
        }
    }

    #[tracing::instrument(skip_all)]
    async fn cast_vote(&self, req: Request<Vote>) -> RPCResult<Status> {
        let vote_req = req.into_inner();

        let Some(token) = self.tokens.lookup_token(&vote_req.token.value).await else {
            return Ok(Response::new(Status::CAST_VOTE_AUTH));
        };
        let Some(voter) = self.voters.find_user_by_name(token.voter_name()).await.ok().flatten() else {
            return Ok(Response::new(Status::CAST_VOTE_AUTH));
        };
        let Ok(Some(mut election)) = self.elections.find_election_by_name(&vote_req.election_name).await else {
            return Ok(Response::new(Status::CAST_VOTE_INVALID));
        };

        if let Ok(result) = self
            .elections
            .vote(&mut election, &voter, &vote_req.choice_name)
            .await
        {
            if let Err(e) = result {
                Ok(Response::new(e.into()))
            } else {
                Ok(Response::new(Status::CAST_VOTE_SUCCESS))
            }
        } else {
            Ok(Response::new(Status::CAST_VOTE_INVALID))
        }
    }

    #[tracing::instrument(skip_all)]
    async fn get_result(&self, req: Request<ElectionName>) -> RPCResult<ElectionResult> {
        let election_name = req.into_inner().name;

        let Ok(Some(election)) = self.elections.find_election_by_name(&election_name).await else {
            return Ok(Response::new(ElectionResult::ELECTION_RESULT_NOTFOUND));
        };
        if !election.is_ended() {
            return Ok(Response::new(ElectionResult::ELECTION_RESULT_ONGOING));
        }

        let vote_counts: Vec<VoteCount> = election
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
        server.tokens.clean_expired_token().await.ok();
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
    let voting = Arc::new(VotingServer {
        dbconn: client.clone(),
        elections: ElectionController::from_db_client(&client).await?,
        voters: VoterController::from_db_client(&client).await?,
        tokens: TokenController::from_db_client(&client).await?,
    });
    tokio::spawn(cronjob_clean_token(voting.clone()));

    info!("Starting server listening on {addr}");
    Server::builder()
        .add_service(VoterRegistrationServer::from_arc(Arc::clone(&voting)))
        .add_service(EVotingServer::from_arc(Arc::clone(&voting)))
        .serve(addr)
        .await?;
    Ok(())
}
