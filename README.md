# tolerant-computing-2023

Project repository for Tolerant Computing 2023 Spring @ NYCU.

## Using Docker

### Build

```
docker build -t voting-system .
```

### Launch Server

```
docker run --network=host -d voting-system
```
or
```
docker run --network=host voting-system voting-server [host]:[port]
```

You must specify `host:port` when using the command.

The first form has a default argument of `127.0.0.1:50001`.

### Run Client

```
docker run --network=host voting-system voting-client [host]:[port]
```

You must specify `host:port` when using the command.

## Using Cargo

### Build

```
cargo build --release
```

### Launch Server

```
cargo run --release --bin voting-server [host]:[port]
```

You must specify `host:port` when using the command.

### Run Client

```
cargo run --release --bin voting-client [host]:[port]
```

You must specify `host:port` when using the command.
