pub mod voting {
    tonic::include_proto!("voting");
}

use std::{env, error::Error};

use tonic::{transport::Server, Request, Response};

#[allow(unused_imports)]
use voting::{
    e_voting_server::{EVoting, EVotingServer},
    AuthRequest, AuthToken, Challenge, Election, ElectionName, ElectionResult, Status, Vote,
    VoteCount, VoterName,
};

type RPCResult<T> = Result<Response<T>, tonic::Status>;

#[derive(Debug, Default)]
struct Voting {}

#[tonic::async_trait]
impl EVoting for Voting {
    async fn pre_auth(&self, _req: Request<VoterName>) -> RPCResult<Challenge> {
        todo!()
    }
    async fn auth(&self, _req: Request<AuthRequest>) -> RPCResult<AuthToken> {
        todo!()
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if let Some(addr_str) = args.get(1) {
        let addr = addr_str.parse()?;
        let voting = Voting::default();
        Server::builder()
            .add_service(EVotingServer::new(voting))
            .serve(addr)
            .await?;
    } else {
        eprintln!("You need to specify host:port to bind!");
    }
    Ok(())
}
