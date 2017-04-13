# Nameserver registration daemon (and client)

Naming of devices on a network is often a tedious procedure, especially
for IPv6 addresses, where there is often no DHCP server that knows about
the devices on the network. Multicast DNS (mdns) discovery can help on
the local network, but there is no authoritative way for a device to
claim a name.

This daemon and associated client is an attempt to provide a solution to
this naming problem.

## How it works

The `nsregd` daemon will allow a client to claim a name on a Trust On
First Use (TOFU) basis using the RFC2136 dynamic DNS update protocol. A
client claims a name by sending a DNS update request with a SIG(0)
(RFC2931) signature and including the public key corresponding to the
signature. If the name in a claim is not already taken by another
client, the client's claim will be successful and the daemon will cache
the public key and use it to verify subsequent update requests.

Once a name has been claimed by a client, that client can add and remove
A and AAAA records by means of regular DNS update requests signed with
the key used to claim the name. The daemon will forward these updates to
one or more configured upstream authoritative nameservers.

Since the main use case for this mechanism is dynamic networks where
clients can come and go without warning, a client is expected to
periodically refresh any name records it creates. The daemon will expire
records and remove them from its upstream servers one TTL (as specified
by the client) after it was last registered. The client is expected to
pick a suitable TTL for the records it creates, such as the lease time
of the IP address in the record. The daemon may enforce a maximum TTL as
well as filter out records; the actual records created and the TTLs
before they are expired are echoed back to the client as part of the
reply to a successful update request.

The daemon will only accept registrations from configured allowed
subnets (and will only listen on TCP to prevent spoofing). Optionally,
subsequent updates can be allowed to point to any IP addresses (to
allow, say, a laptop to register itself on its home network while away
from home). Clients are only allowed to register names that are one
level below the configured zone name, and names can be reserved by
configuration. Currently, any upstream servers supporting
TSIG-authenticated updates are supported.

## The client

The `nsregc` client included here is an implementation of a client that
will speak to the daemon as per the description above and register any
addresses found on the local machine with a configured name. The client
is given one or more zones to register with, and will attempt to find a
compatible `nsregd` server by querying for a SRV record at the name
`_nsreg._tcp.<zone>`. If such a server is found, the client will register
A and AAAA records corresponding to each of the local addresses of the
machine, and maintain these registrations until killed. In addition, the
client will attempt to listen for address addition and removal events
via the Linux Netlink interface, and update the records accordingly. The
TTL for the created records is taken from the address validity as
reported by the kernel, clamped to a configurable maximum value.

## Building
Both `nsregd` and `nsregc` are written in Go. To build, you will need a
working Go build environment.

1. Make sure the `$GOPATH` environment variable is set to a suitable
   value.
2. Run `make dep` to get the Go dependencies.
3. Run `make` to build both binaries.

## Running
To run the `nsregd` daemon:
1. Pick a zone under which clients will be able to register names, such
   as  `dynamic.example.org`.
2. Generate a TSIG secret and configure the authoritative DNS server for
   the parent zone (`example.org` in the example above) to allow updates
   to the registration zone with this secret.
3. Edit `nsregd.conf.example` to contain the chosen zone name and to point
   at the right upstream server and set the TSIG secret.
4. Run `nsregd` with `-conffile` parameter pointing to the right file.
5. Add a SRV record at `_nsreg._tcp.dynamic.example.org` pointing to the
   hostname and port that `nsregd` is listening on.

To run the `nsregc` client:
1. Edit `nsregc.conf.example` to set the name the client should try to
   claim, the interfaces to get IP addresses from, and the files
   containing the public and private keys used for signing.
2. Either generate a key pair using `dnssec-keygen` (any algorithm
   suitable for SIG(0) signing will work), or run `nsregc` with the
   `-genkey` parameter.
3. Run `nsregc` with the zone(s) you wish to register with as command
   line parameters.

To make `nsregc` use a specific name server to do the initial SRV
lookup, pass a server hostname prefixed with a `@` and optionally set
the `-port` and `-tcp` flags. For testing, it is possible to point
`nsregc` directly at `nsregd` for the initial query (since `nsregd` will
reply with its own address to any SRV queries).

## Limitations

This is still alpha quality software. In particular, the code has had NO
external security review, so use at your own risk. In particular, it is
recommended to configure your authoritative DNS server to only allow
`nsregd` to update its own zone.

Other limitations, in no particular order:

- There is currently no way for the client to discover which zone to
  register with on its own. Getting the zone name from (e.g.) DHCP would
  be a way to deal with this.

- If communication between `nsregd` and the upstream server(s) fail, no
  retries are currently performed. If the failure occurs while the
  client is first registering, the failure will be reported to the
  client, but if the failure occurs while entries are being
  automatically expired, it can result in records being left behind in
  the upstream DNS.

- There is not a lot of error checking done on the configuration values.
  If you get them wrong, the respective binary is likely to crash on
  you.

- If subscribing to netlink fails, the client will be oblivious to any
  new addresses that appear on the configured interface(s).

- While `nsregd` tries not to send too many updates to the authoritative
  server, it could be smarter about this. For instance, using the
  prerequisites feature of RFC2136 could be a way to bring down the
  number of updates.

- In some cases, the cache logic will end up doing a linear search
  through all cached records.

- To repeat: There has been NO external security review. I've done my
  best to get it right, but for all I know it may eat your lunch (and
  your DNS zone).


The above is not meant to be an exhaustive list: There are probably
other bugs! If you find any, please do report them (or even better, send
a patch!).
