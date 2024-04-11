# Failover
Failover is a VRRP implementation currently configured for debian instances.

## Config 
The following are the configurations that can be made on a <u>Failover</u> Virtual Router:

    - *name 
    - *Virtual Router ID
    - *Ip Addresses 
    - *Interface Name
    - Priority (default - 100)
    - Advertisement Interval ( default - 1)
    - Preempt Mode[true/false] ( default - true )

    * Compulsory fields.  

Failover can fetch configuration parameters either from the cli arguments or from a JSON file. 

You can specify which mode you want to use by either having the `--file [FILENAME]` or `--cli [ARGS]`

### File config

We collect file configs from a JSON file. Assuming our configs is in a `my-config.json` file, 
this is how the `my-config.json` file should look like:

```json
{
    "name": "VR_1",
    "vrid": 51,
    "interface_name": "wlo1",
    "ip_addresses": [ 
        "192.168.100.100/24"
    ],
    "priority": 10,
    "advert_interval": 1,
    "preempt_mode": true
}
```

To use this file as the configuration for our failover instance, we will run:
```sh
./failover --file my-config.json
```

### Default config 
When run without a `--file [FILENAME]` nor `--cli [ARGS]` specified, the `/etc/failover/vrrp-config.json` file will be used by default as the configuration file. 

Can be run with:
```sh
./failover
```
This will automatically look into your `/etc/failover/vrrp-config.json` file and use its parameters as the config 
for the virtual router we are going to create. 

To look into how the JSON configs, look in the File Config section. 

### Cli config
Taking configs from the CLI, we have to specify run `./failover --cli [ARGS]`. to see all valid inputs  for the `[ARGS]`. 

For a comprehensive list of the fields that can be taken inside the `[ARGS]`, run `./failover --help`. 

A sample command taking CLI VRRP configs:

```sh
sudo ./target/debug/failover --cli --name VR_1 --vrid 51 --iface wlo1 --ip-address 192.168.100.100/24 --priority 10 --adv-interval 1 --preempt-mode true 
```

## Actions

Actions are what should be done with the configs set. 

There are three actions: `setup`, `teardown` and `run`. 

- `setup`: This takes each of the IP addresses specified in our configuration and adds them to as address(es) on the network interface specified. 
- `run`(default): When no action has been specified, this is what will be called. This carries out the necessary network advertisements. 
- `teardown`: This removes the IP addresses that have been specified in the config from the network interface. 

NOTE: It is recommended to run `setup`, then `run` and finally `teardown`. An example of how to do this is specified in the `run.sh` file. 

Example:
```bash
./failover --action setup # will use vrrp-config.json as config file setup as action. 
./failover # will use vrrp-config.json as config file and run as action. 
./failover --action teardown # will use vrrp-config.json as config as teardown as action. 
```

