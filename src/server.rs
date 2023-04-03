pub mod voting {
    tonic::include_proto!("voting");
}

use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use dashmap::{mapref::entry::Entry, DashMap};
use ed25519_dalek::{Signature, Verifier};
use tokio::time::MissedTickBehavior;
use tonic::{transport::Server, Request, Response};

use voting::{
    e_voting_server::{EVoting, EVotingServer},
    voter_registration_server::{VoterRegistration, VoterRegistrationServer},
    AuthRequest, AuthToken, Challenge, Election, ElectionName, ElectionResult, Status, Vote,
    VoteCount, Voter, VoterName,
};

mod internal_voter;
mod token_manager;

use internal_voter::InternalVoter;
use token_manager::{TokenManager, VoterToken};

type RPCResult<T> = Result<Response<T>, tonic::Status>;

#[derive(Debug, Default)]
struct VotingServer {
    // voters: A map that stores the voters that is registered.
    // key: Name of the voter.
    // value: Internal voter representation.
    voters: DashMap<String, InternalVoter>,
    // tokens: A map that stores token and the handle to the token expiration callback.
    // Use `contains_key` to verify if a token is valid.
    // key: Sha512 of the auth token, stored in base64.
    // value: Handle to the token expiration callback.
    tokens: TokenManager,
}

#[tonic::async_trait]
impl VoterRegistration for VotingServer {
    async fn register_voter(&self, req: Request<Voter>) -> RPCResult<Status> {
        let v = req.into_inner();

        match self.voters.entry(v.name.clone()) {
            Entry::Occupied(_) => Ok(Response::new(Status { code: 1 })),
            Entry::Vacant(e) => {
                let Ok(ivoter) = InternalVoter::try_from(v) else {
                    eprintln!("Malformed public key");
                    return Ok(Response::new(Status { code: 2 }));
                };
                e.insert(ivoter);

                Ok(Response::new(Status { code: 0 }))
            }
        }
    }

    async fn unregister_voter(&self, req: Request<VoterName>) -> RPCResult<Status> {
        let n = req.into_inner();

        if self.voters.remove(&n.name).is_some() {
            Ok(Response::new(Status { code: 0 }))
        } else {
            Ok(Response::new(Status { code: 1 }))
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
    async fn auth(&self, req: Request<AuthRequest>) -> RPCResult<AuthToken> {
        let auth_req = req.into_inner();
        let name = &auth_req.name.name;
        let err_resp = Ok(Response::new(AuthToken {
            value: vec![0; 128],
        }));

        let Some(mut voter_entry) = self.voters.get_mut(name) else {
            eprintln!("No such voter or challenge.");
            return err_resp;
        };
        let (Ok(sig), Some(msg)) = (
            Signature::from_bytes(&auth_req.response.value),
            voter_entry.take_challenge(),
        ) else {
            eprintln!("Invalid Signature.");
            return err_resp;
        };
        let pubk = voter_entry.public_key();

        match pubk.verify(&msg, &sig) {
            Ok(()) => Ok(Response::new(AuthToken {
                value: Vec::from(self.tokens.generate_token(voter_entry.name())),
            })),
            Err(e) => {
                eprintln!("Challenge-Response failed: {}", e);
                err_resp
            }
        }
    }

    async fn create_election(&self, _req: Request<Election>) -> RPCResult<Status> {
        todo!()
    }
    async fn cast_vote(&self, _req: Request<Vote>) -> RPCResult<Status> {
        todo!()
    }
    async fn get_result(&self, req: Request<ElectionName>) -> RPCResult<ElectionResult> {
        eprintln!(
            "Request for election result of election <{}>",
            req.get_ref().name
        );
        let vote_count = VoteCount {
            choice_name: "Test".to_string(),
            count: 999,
        };
        let result = ElectionResult {
            status: 0,
            count: vote_count,
        };
        Ok(Response::new(result))
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'H', long)]
    host: IpAddr,
    #[arg(short, long, default_value_t = 50001)]
    port: u16,
}

async fn cronjob_clean_token(server: Arc<VotingServer>) {
    let mut interval = tokio::time::interval(Duration::from_secs(600));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        server.tokens.clean_expired_token();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let addr = SocketAddr::from((args.host, args.port));
    let voting = Arc::new(VotingServer::default());
    tokio::spawn(cronjob_clean_token(voting.clone()));

    Server::builder()
        .add_service(VoterRegistrationServer::from_arc(Arc::clone(&voting)))
        .add_service(EVotingServer::from_arc(Arc::clone(&voting)))
        .serve(addr)
        .await?;
    Ok(())
}
