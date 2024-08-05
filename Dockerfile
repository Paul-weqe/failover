FROM rust:1.76.0

RUN apt update && apt install -y iproute2

WORKDIR /failover
COPY . /failover/

RUN cargo build 


CMD [ "./target/debug/failover", "file-mode" ]
