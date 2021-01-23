# Smart VPN client

Performs all the standard functions of a VPN client, i.e. manages a connection to a VPN headend. The "smart" functionality includes:

* Automatic discovery and probing of all available VPN headends. The client will connect to the headend with the lowest round-trip time.
* Automatic management of routing and NAT masquerade rules required for a VPN client.
* Periodic VPN connection healthchecks - if more than 3 consecutive healthchecks fail, connection is automatically re-established.
* VPN connection QoS tracking -- takes a baseline round-trip time measurement when a new connection is established and triggers reconnect when the average latency exceeds 2 x baseline.


## Supported Providers

* [Private Internet Access](https://www.privateinternetaccess.com/) with Wireguard as the VPN tunnel transport (requires wireguard kernel module).


## Installation

To install run:

```
go get github.com/networkop/smart-vpn-client
```

The binary can be found in `$GOPATH/bin/`:

```
# ls -lah $GOPATH/bin/smart-vpn-client
-rwxr-xr-x 1 root root 7.9M Jan 23 14:57 /go/bin/smart-vpn-client
```


## Run

The binary requires `NET_ADMIN` capabilities in order to set up interfaces and manipulate routing, therefore the simplest way is to run it with `sudo`:

```
sudo VPN_PWD=<VPN_PASSWORD> ./smart-vpn-client -user <VPN_USERNAME>
```

## Manual build

Clone this repo and run: 

```
make
```