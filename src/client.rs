pub mod voting {
    tonic::include_proto!("voting");
}

use std::{env, error::Error};

use voting::{e_voting_client::EVotingClient, ElectionName};

use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if let Some(addr_str) = args.get(1) {
        let rpc_target = format!("http://{}", addr_str);
        let mut client = EVotingClient::connect(rpc_target).await?;

        let req = Request::new(ElectionName {
            name: "Test Election".to_string(),
        });

        let resp = client.get_result(req).await?;
        eprintln!("GetResult response = {:?}", resp);
    } else {
        eprintln!("You need to specify a target (e.g. http://[host]:[port]) to do gRPC!");
    }
    Ok(())
}
