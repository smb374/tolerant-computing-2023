pub mod voting {
    tonic::include_proto!("voting");
}

use std::{env, error::Error, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine};
use dashmap::DashMap;
use ed25519_dalek::{Digest, PublicKey, Sha512, Signature, SignatureError, Verifier};
use flume::{Receiver, Sender};
use rand_core::{OsRng, RngCore};
use tokio::task::JoinHandle;
use tonic::{transport::Server, Request, Response};

use voting::{
    e_voting_server::{EVoting, EVotingServer},
    voter_registration_server::{VoterRegistration, VoterRegistrationServer},
    AuthRequest, AuthToken, Challenge, Election, ElectionName, ElectionResult, Status, Vote,
    VoteCount, Voter, VoterName,
};

type RPCResult<T> = Result<Response<T>, tonic::Status>;

/// Internal voter representation.
///
/// name: Voter name.
/// group: Voter group.
/// public_key: Ed25519 public key for authentication.
/// challenge: temporary challenge store for verifying response.
/// token: Sha512 of the auth token in base64.
#[derive(Debug)]
struct InternalVoter {
    name: String,
    group: String,
    public_key: PublicKey,
    challenge: Option<[u8; 128]>,
    token: Option<String>,
}

impl TryFrom<Voter> for InternalVoter {
    type Error = SignatureError;
    fn try_from(value: Voter) -> Result<Self, Self::Error> {
        let public_key = PublicKey::from_bytes(&value.public_key)?;
        Ok(Self {
            name: value.name,
            group: value.group,
            public_key,
            challenge: None,
            token: None,
        })
    }
}

#[derive(Debug)]
struct VotingServer {
    // voters: A map that stores the voters that is registered.
    // key: Name of the voter.
    // value: Internal voter representation.
    voters: DashMap<String, InternalVoter>,
    // tokens: A map that stores token and the handle to the token expiration callback.
    // Use `contains_key` to verify if a token is valid.
    // key: Sha512 of the auth token, stored in base64.
    // value: Handle to the token expiration callback.
    tokens: DashMap<String, JoinHandle<()>>,
    token_notify_channel: (Sender<String>, Receiver<String>),
}

impl Default for VotingServer {
    fn default() -> Self {
        Self {
            voters: DashMap::default(),
            tokens: DashMap::default(),
            token_notify_channel: flume::unbounded(),
        }
    }
}

#[tonic::async_trait]
impl VoterRegistration for VotingServer {
    async fn register_voter(&self, req: Request<Voter>) -> RPCResult<Status> {
        let v = req.into_inner();
        match InternalVoter::try_from(v) {
            Ok(v) => {
                if self.voters.contains_key(&v.name) {
                    Ok(Response::new(Status { code: 1 }))
                } else {
                    self.voters.insert(v.name.to_owned(), v);
                    Ok(Response::new(Status { code: 0 }))
                }
            }
            Err(e) => {
                eprintln!("Malformed public key: {}", e);
                Ok(Response::new(Status { code: 2 }))
            }
        }
    }
    async fn un_register_voter(&self, req: Request<VoterName>) -> RPCResult<Status> {
        let n = req.into_inner();
        if self.voters.contains_key(&n.name) {
            self.voters.remove(&n.name);
            Ok(Response::new(Status { code: 0 }))
        } else {
            Ok(Response::new(Status { code: 1 }))
        }
    }
}

fn digest64(data: &[u8]) -> String {
    let dgst = Sha512::digest(data);
    STANDARD.encode(dgst.as_slice())
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
            let mut buf: [u8; 128] = [0; 128];
            OsRng.fill_bytes(&mut buf);
            v.challenge.replace(buf.clone());
            Ok(Response::new(Challenge {
                value: Vec::from(buf),
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
        let r = Ok(Response::new(AuthToken {
            value: vec![0; 128],
        }));
        if let Some(v) = self.voters.get_mut(name).as_mut() {
            let pubk = v.public_key;
            if let (Ok(sig), Some(msg)) = (
                Signature::from_bytes(&auth_req.response.value),
                v.challenge.take(),
            ) {
                match pubk.verify(&msg, &sig) {
                    Ok(()) => {
                        if let Some(k) = v.token.take() {
                            if let Some((_, h)) = self.tokens.remove(&k) {
                                h.abort();
                            }
                        }
                        let mut buf = [0u8; 128];
                        OsRng.fill_bytes(&mut buf);
                        let dgst = digest64(&buf);
                        let d = dgst.clone();
                        let tx = self.token_notify_channel.0.clone();
                        let handle = tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                            let _ = tx.send_async(d).await;
                        });
                        self.tokens.insert(dgst.clone(), handle);
                        v.token.replace(dgst);
                        Ok(Response::new(AuthToken {
                            value: Vec::from(buf),
                        }))
                    }
                    Err(e) => {
                        eprintln!("Challenge-Response failed: {}", e);
                        r
                    }
                }
            } else {
                eprintln!("Invalid Signature.");
                r
            }
        } else {
            eprintln!("No such voter or challenge.");
            r
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

impl VotingServer {
    /// A task that removes the entry from self.tokens once the expiration callback of the auth
    /// token send itself to the channel.
    async fn token_expiration_handle(self: Arc<Self>) {
        loop {
            match self.token_notify_channel.1.recv_async().await {
                Ok(k) => {
                    if let Some((_, h)) = self.tokens.remove(&k) {
                        // callback should be finished by here.
                        if !h.is_finished() {
                            h.abort();
                        }
                    }
                }
                Err(_e) => {
                    break;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if let Some(addr_str) = args.get(1) {
        let addr = addr_str.parse()?;
        let voting = Arc::new(VotingServer::default());
        tokio::spawn(Arc::clone(&voting).token_expiration_handle());
        Server::builder()
            .add_service(VoterRegistrationServer::from_arc(Arc::clone(&voting)))
            .add_service(EVotingServer::from_arc(Arc::clone(&voting)))
            .serve(addr)
            .await?;
    } else {
        eprintln!("You need to specify host:port to bind!");
    }
    Ok(())
}
