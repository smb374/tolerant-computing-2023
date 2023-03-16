FROM rust:latest

RUN apt-get update
RUN apt-get install -y protobuf-compiler
