pub mod voting {
    tonic::include_proto!("voting");
}

use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, SocketAddr},
};

use base64::prelude::{Engine, BASE64_STANDARD};
use clap::{Command, FromArgMatches, Parser, Subcommand};
use ed25519_dalek::{
    ed25519::signature::{Signature, SignerMut},
    Keypair,
};
use rand_core::OsRng;
use rustyline::{error::ReadlineError, DefaultEditor};
use tonic::{transport::Channel, Request};

use voting::{
    e_voting_client::EVotingClient, voter_registration_client::VoterRegistrationClient,
    AuthRequest, Voter, VoterName,
};

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
    #[command(about = "Exit shell.")]
    Exit,
}

/// Repl shell command handler
///
/// Handles the command that the repl shell received.
async fn handle_commands(
    reg: &mut VoterRegistrationClient<Channel>,
    vote: &mut EVotingClient<Channel>,
    users: &mut HashMap<String, ClientVoter>,
    cmds: Commands,
) -> Result<bool, Box<dyn Error>> {
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
            let resp = reg.register_voter(req).await?;
            if resp.get_ref().code == 0 {
                users.insert(cv.name.to_owned(), cv);
                println!("Register success.");
            } else {
                println!("Register failed with code = {}", resp.get_ref().code);
            }
        }
        Commands::Unregister { name } => {
            let req = Request::new(VoterName { name: name.clone() });
            let resp = reg.unregister_voter(req).await?;
            if resp.get_ref().code == 0 {
                users.remove(&name);
                println!("Unregister success.");
            } else {
                println!("Unregister failed with code = {}", resp.get_ref().code);
            }
        }
        Commands::Auth { name } => {
            if let Some(cv) = users.get_mut(&name).as_mut() {
                let ch_resp = vote
                    .pre_auth(Request::new(VoterName { name: name.clone() }))
                    .await?;
                let challenge = ch_resp.get_ref().value.as_slice();
                if challenge != &[0u8; 128] {
                    let response = cv.key_pair.sign(&challenge).as_bytes().to_vec();
                    let auth_resp = vote
                        .auth(Request::new(AuthRequest {
                            name: VoterName { name: name.clone() },
                            response: voting::Response { value: response },
                        }))
                        .await?;
                    let token = auth_resp.get_ref().value.as_slice();
                    if token != &[0u8; 128] {
                        println!("Got auth token: {}", BASE64_STANDARD.encode(token));
                        cv.token.replace(token.to_vec());
                    }
                }
            }
        }
        Commands::Exit => {
            cleanup(reg, users).await?;
            return Ok(true);
        }
        _ => {
            println!("cmds: {:?}", cmds);
        }
    }
    Ok(false)
}

async fn cleanup(
    reg: &mut VoterRegistrationClient<Channel>,
    users: &mut HashMap<String, ClientVoter>,
) -> Result<(), Box<dyn Error>> {
    for entry in users.iter() {
        let req = Request::new(VoterName {
            name: entry.0.clone(),
        });
        let resp = reg.unregister_voter(req).await?;
        if resp.get_ref().code != 0 {
            println!(
                "Unregister user {} failed with code = {}",
                entry.0,
                resp.get_ref().code
            );
        }
    }
    users.clear();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let addr = SocketAddr::from((args.host, args.port));
    let endpoint = format!("http://{}/", addr);
    let mut register_client = VoterRegistrationClient::connect(endpoint.clone()).await?;
    let mut vote_client = EVotingClient::connect(endpoint).await?;
    let mut user_map: HashMap<String, ClientVoter> = HashMap::new();

    let mut rl = DefaultEditor::new()?;

    loop {
        let line = rl.readline("$> ");
        match line {
            Ok(line) => {
                rl.add_history_entry(&line)?;
                match shell().try_get_matches_from(line.split_whitespace()) {
                    Ok(matches) => {
                        let cmds = Commands::from_arg_matches(&matches)?;
                        match handle_commands(
                            &mut register_client,
                            &mut vote_client,
                            &mut user_map,
                            cmds,
                        )
                        .await
                        {
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
                cleanup(&mut register_client, &mut user_map).await?;
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
