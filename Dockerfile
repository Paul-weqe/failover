FROM rust:1.97.1

ARG PROFILE=release

WORKDIR /failover
COPY . /failover/

RUN cargo build --profile $PROFILE && \
  cp target/$PROFILE/failover /usr/local/sbin/failover
