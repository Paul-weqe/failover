#!/bin/bash 

cargo build 
sudo ./target/debug/failover run file-mode --filename sample-vrrp-config.json --log-file-path /var/log/failover.log
pid=$!
wait $pid
sudo ./target/debug/failover teardown file-mode --filename sample-vrrp-config.json 
