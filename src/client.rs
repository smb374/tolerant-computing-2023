pub mod voting {
    tonic::include_proto!("voting");
}

use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
};

use clap::Parser;
use tonic::Request;

use voting::{e_voting_client::EVotingClient, ElectionName};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'H', long)]
    host: IpAddr,
    #[arg(short, long, default_value_t = 50001)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let addr = SocketAddr::from((args.host, args.port));
    let mut client = EVotingClient::connect(format!("http://{}/", addr)).await?;

    let req = Request::new(ElectionName {
        name: "Test Election".to_string(),
    });

    let resp = client.get_result(req).await?;
    eprintln!("GetResult response = {:?}", resp);
    Ok(())
}
