#!/bin/bash 

cargo build 
sudo ./target/debug/failover 
sudo ./target/debug/failover
pid=$!
wait $pid
sudo ./target/debug/failover --action teardown 

