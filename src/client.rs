pub mod voting {
    tonic::include_proto!("voting");
}

use std::error::Error;

use voting::{e_voting_client::EVotingClient, ElectionName};

use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut client = EVotingClient::connect("http://127.0.0.1:50001").await?;

    let req = Request::new(ElectionName {
        name: "Test Election".to_string(),
    });

    let resp = client.get_result(req).await?;
    eprintln!("GetResult response = {:?}", resp);
    Ok(())
}
