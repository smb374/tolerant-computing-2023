FROM rust:slim-bullseye AS builder

RUN apt-get update && apt-get install -y protobuf-compiler libprotobuf-dev

WORKDIR /usr/src/voting-system

COPY Cargo.toml .
COPY Cargo.lock .

# Download the package separately to generate cache for rebuild
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN cargo fetch

COPY . .

RUN cargo install --path .

# Runtime Image
FROM debian:bullseye-slim

COPY --from=builder /usr/local/cargo/bin/voting-server /usr/local/bin/
COPY --from=builder /usr/local/cargo/bin/voting-client /usr/local/bin/

CMD ["voting-server"]
