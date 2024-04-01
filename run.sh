#!/bin/bash 

cargo build 
sudo ./target/debug/failover --json-file vrrp-config.json --action startup
sudo ./target/debug/failover --json-file vrrp-config.json --action run
pid=$!
wait $pid
sudo ./target/debug/failover --json-file vrrp-config.json --action teardown

