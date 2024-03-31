#!/bin/bash 

cargo build 

# create the IP addresses
sudo ./target/debug/create_addresses
sudo ./target/debug/failover
pid=$!
wait $pid
sudo ./target/debug/delete_addresses
