

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/failover)


# Failover

### Config 
The following are the items that can be configured on <u>Failover</u>:

    - *name 
    - *Virtual Router ID
    - *Ip Addresses 
    - *Interface Name
    - Priority (default - 100)
    - Advertisement Interval ( default - 1)
    - Preempt Mode[true/false] ( default - true )

    * Compulsory fields.  


## Installation via snap
Failover is a VRRP implementation currently configured for debian instances.

To install failover, run the following command:

```sh
snap install failover --devmode --edge
```
with this, we should see failover when we run the `snap list` command.

*Due to restrictions from the snap store, we can only run --edge and --beta*

When failover is installed, it automatically starts a systemd service that can be viewed via systemstl. 
When we `sudo systemctl status snap.failover.main.service`, we should see:

![systemctl screenshot](images/failover.png)

That indicates that Failover is running as a daemon in on our system. 

If there is a problem with the running of Failover, view the logs with the following command:
```sh
journalctl -xeu snap.failover.setup.service
```

Also, feel free to raise an [issue](https://github.com/Paul-weqe/failover/issues) in case of anything.  

When installed via snap, Failover fetches configurations from `/var/snap/failover/common/vrrp-config.json` file by default. The configurations 

**Make sure to change the fields in this `/var/snap/failover/common/vrrp-config.json` file to suite your personal environment. Sample configs are shown on [sample config](https://github.com/Paul-weqe/failover/blob/main/sample-vrrp-config.json).**


## Running Failover from local build. 

Failover can also be built and run manually via cargo. To install cargo, follow [this guide](https://doc.rust-lang.org/cargo/getting-started/index.html).

You can run the project using the command:
```sh
cargo run --bin failover
```

Since VRRP creates virtual IP addresses on one of our system's interfaces, we should do a teardown to remove the IP addresses from the system once Failover is done running:
```sh
cargo run --bin failover --teardown
```

To simplify the two commands above, we can run: 

```sh
./run
```

When running from a local build, by default the `/etc/failover/vrrp-config.json` file will be used as our configuration file. Take [this](https://github.com/Paul-weqe/failover/blob/main/sample-vrrp-config.json) as a sample of how your JSON config file should look like. 

$\text{\color{red}More documentation is still being worked on.}$

Will be ready to view in due time [here](https://failover-docs.readthedocs.io/en/latest/). 