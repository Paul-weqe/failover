#!/bin/bash 

cargo build 
sudo ./target/debug/failover --action startup
sudo ./target/debug/failover 
pid=$!
wait $pid
sudo ./target/debug/failover --action teardown

