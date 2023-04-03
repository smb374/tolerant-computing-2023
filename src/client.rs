use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, SocketAddr},
};

use base64::prelude::{Engine, BASE64_STANDARD};
use clap::{Command, FromArgMatches, Parser, Subcommand};
use ed25519_dalek::{
    ed25519::signature::{Signature, SignerMut},
    Digest, Keypair, Sha512,
};
use rand_core::OsRng;
use rustyline::{error::ReadlineError, DefaultEditor};
use tonic::{
    transport::{self, Channel},
    Request,
};

use voting::{
    e_voting_client::EVotingClient, voter_registration_client::VoterRegistrationClient,
    AuthRequest, Voter, VoterName,
};

pub mod voting;

struct ClientVoter {
    name: String,
    group: String,
    key_pair: Keypair,
    token: Option<Vec<u8>>,
}

/// Command line arguments
///
/// host: IP Address, V4 or V6.
/// port: TCP port number, default = 50001
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'H', long)]
    host: IpAddr,
    #[arg(short, long, default_value_t = 50001)]
    port: u16,
}

/// Repl shell command
///
/// Add repl shell command here with arguments and help string.
#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Register a user to the voting server.")]
    Register {
        #[arg(help = "Name of the user.")]
        name: String,
        #[arg(help = "Group of the user.")]
        group: String,
    },
    #[command(about = "Unregister a user from the voting server.")]
    Unregister {
        #[arg(help = "Name of the user.")]
        name: String,
    },
    #[command(about = "Perform challenge-response authentication to get a auth token.")]
    Auth {
        #[arg(help = "Name of the user.")]
        name: String,
    },
    #[command(about = "List various states of the client.")]
    #[command(subcommand)]
    List(List),
    #[command(about = "Exit shell.")]
    Exit,
}

#[derive(Subcommand, Debug)]
enum List {
    #[command(about = "List registerted users in this client.")]
    User,
}

struct VotingClient {
    registeration: VoterRegistrationClient<Channel>,
    evoting: EVotingClient<Channel>,
    user_map: HashMap<String, ClientVoter>,
}

impl VotingClient {
    async fn new(args: Args) -> Result<Self, transport::Error> {
        let addr = SocketAddr::from((args.host, args.port));
        let endpoint = format!("http://{}/", addr);
        let registeration = VoterRegistrationClient::connect(endpoint.clone()).await?;
        let evoting = EVotingClient::connect(endpoint).await?;
        let user_map: HashMap<String, ClientVoter> = HashMap::new();
        Ok(Self {
            registeration,
            evoting,
            user_map,
        })
    }
    /// Repl shell command handler
    ///
    /// Handles the command that the repl shell received.
    async fn handle_commands(&mut self, cmds: Commands) -> Result<bool, tonic::Status> {
        match cmds {
            Commands::Register { name, group } => {
                let mut csprng = OsRng::default();
                let key_pair = Keypair::generate(&mut csprng);
                let cv = ClientVoter {
                    name,
                    group,
                    key_pair,
                    token: None,
                };
                let req = Request::new(Voter {
                    name: cv.name.clone(),
                    group: cv.group.clone(),
                    public_key: Vec::from_iter(cv.key_pair.public.as_bytes().clone().into_iter()),
                });
                let resp = self.registeration.register_voter(req).await?;
                if resp.get_ref().code == 0 {
                    self.user_map.insert(cv.name.to_owned(), cv);
                    println!("Register success.");
                } else {
                    println!("Register failed with code = {}", resp.get_ref().code);
                }
            }
            Commands::Unregister { name } => {
                let req = Request::new(VoterName { name: name.clone() });
                let resp = self.registeration.unregister_voter(req).await?;
                if resp.get_ref().code == 0 {
                    self.user_map.remove(&name);
                    println!("Unregister success.");
                } else {
                    println!("Unregister failed with code = {}", resp.get_ref().code);
                }
            }
            Commands::Auth { name } => {
                if let Some(cv) = self.user_map.get_mut(&name).as_mut() {
                    let ch_resp = self
                        .evoting
                        .pre_auth(Request::new(VoterName { name: name.clone() }))
                        .await?;
                    let challenge = ch_resp.get_ref().value.as_slice();
                    if challenge != &[0u8; 128] {
                        let response = cv.key_pair.sign(&challenge).as_bytes().to_vec();
                        let auth_resp = self
                            .evoting
                            .auth(Request::new(AuthRequest {
                                name: VoterName { name: name.clone() },
                                response: voting::Response { value: response },
                            }))
                            .await?;
                        let token = auth_resp.get_ref().value.as_slice();
                        if token != &[0u8; 128] {
                            println!("Authentication success.");
                            cv.token.replace(token.to_vec());
                        }
                    }
                }
            }
            Commands::List(l) => match l {
                List::User => {
                    self.user_map.iter().for_each(|(_, v)| {
                        let token = if let Some(tok) = v.token.as_ref() {
                            sha512_dgst(tok)
                        } else {
                            String::from("nil")
                        };
                        let pubk = sha512_dgst(&v.key_pair.public.to_bytes());
                        println!("name: {}", v.name);
                        println!("group: {}", v.group);
                        println!("public key: sha512:{}", pubk);
                        println!("auth token: sha512:{}", token);
                        print!("\n");
                    });
                }
            },
            Commands::Exit => {
                self.cleanup().await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn cleanup(&mut self) -> Result<(), tonic::Status> {
        for entry in self.user_map.iter() {
            let req = Request::new(VoterName {
                name: entry.0.clone(),
            });
            let resp = self.registeration.unregister_voter(req).await?;
            if resp.get_ref().code != 0 {
                println!(
                    "Unregister user {} failed with code = {}",
                    entry.0,
                    resp.get_ref().code
                );
            }
        }
        self.user_map.clear();
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut client = VotingClient::new(args).await?;

    let mut rl = DefaultEditor::new()?;

    loop {
        let line = rl.readline("$> ");
        match line {
            Ok(line) => {
                rl.add_history_entry(&line)?;
                match shell().try_get_matches_from(line.split_whitespace()) {
                    Ok(matches) => {
                        let cmds = Commands::from_arg_matches(&matches)?;
                        match client.handle_commands(cmds).await {
                            Ok(exit) => {
                                if exit {
                                    break;
                                }
                            }
                            Err(e) => {
                                println!("An error occurred when handling repl command: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}", e.render().ansi());
                    }
                }
            }
            Err(ReadlineError::Eof | ReadlineError::Interrupted) => {
                client.cleanup().await?;
                println!("Exit...");
                break;
            }
            Err(e) => {
                println!("Error occurred: {}", e);
                break;
            }
        }
    }
    Ok(())
}

fn shell() -> Command {
    const PARSER_TEMPLATE: &str = "\
        {all-args}
    ";

    let cli = Command::new("repl")
        .multicall(true)
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand_value_name("APPLET")
        .subcommand_help_heading("APPLETS")
        .help_template(PARSER_TEMPLATE);

    Commands::augment_subcommands(cli)
}

fn sha512_dgst(data: &[u8]) -> String {
    let dgst = Sha512::digest(data);
    BASE64_STANDARD.encode(dgst)
}
