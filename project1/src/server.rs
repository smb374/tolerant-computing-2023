use std::io;

pub mod voting {
    tonic::include_proto!("voting");
}

#[tokio::main]
async fn main() -> io::Result<()> {
    Ok(())
}
