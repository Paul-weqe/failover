#!/bin/bash 

cargo build 
sudo ./target/debug/failover --file sample-vrrp-config.json --action setup
sudo ./target/debug/failover --file sample-vrrp-config.json
pid=$!
wait $pid
sudo ./target/debug/failover --file sample-vrrp-config.json --action teardown

