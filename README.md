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

### Run Client

```
docker run --network=host voting-system voting-client
```

## Using Cargo

### Build

```
cargo build --release
```

### Launch Server

```
cargo run --release --bin voting-server
```

### Run Client

```
cargo run --release --bin voting-client
```
