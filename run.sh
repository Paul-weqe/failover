#!/bin/bash 

cargo build 
sudo ./target/debug/failover file-mode --filename sample-vrrp-config.json
pid=$!
wait $pid
sudo ./target/debug/failover --action teardown 

