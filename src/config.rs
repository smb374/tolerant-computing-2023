use crate::args::ServerArgs;
use std::net::{IpAddr, Ipv6Addr};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    pub database: DatabaseConfig,
}

impl ServerConfig {
    pub fn merge_from_args(&mut self, args: &ServerArgs) {
        if let Some(host) = args.host {
            self.host = host;
        }
        if let Some(port) = args.port {
            self.port = port;
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DatabaseConfig {
    pub uri: String,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    pub timeout: Option<u64>,
}

fn default_host() -> IpAddr {
    Ipv6Addr::LOCALHOST.into()
}

fn default_port() -> u16 {
    50001
}

fn default_prefix() -> String {
    String::from("voting_server")
}
