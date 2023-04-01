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
docker run --network=host voting-system voting-server -H [host] -p [port]
```

You must specify `host` when using the command.

The `port` has a default value of `50001`.

The first command binds on `127.0.0.1:50001`.


### Run Client

```
docker run --network=host voting-system voting-client -H [host] -p [port]
```

You must specify `host` and `port` of the server when using the command.

## Using Cargo

### Build

```
cargo build --release
```

### Launch Server

```
cargo run --release --bin voting-server -H [host] -p [port]
```

You must specify `host` and `port` when using the command.

### Run Client

```
cargo run --release --bin voting-client -H [host] -p [port]
```

You must specify `host` and `port` of the server when using the command.
