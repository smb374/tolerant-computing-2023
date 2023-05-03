use clap::Parser;
use std::net::IpAddr;

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ServerArgs {
    #[arg(short = 'c', long, default_value = "config")]
    pub config: String,
    #[arg(short = 'H', long)]
    pub host: Option<IpAddr>,
    #[arg(short, long)]
    pub port: Option<u16>,
}
