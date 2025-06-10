# MITM 

A https main-in-the-middle proxy, built using [Pingora Proxy](https://docs.rs/pingora). 

The proxy automatically generates (or if it exists, loads) a Certificate Authority, PEM encoded, at `~/.mitm/ca.crt` and `~/.mitm/ca.key`.  

> **NOTE:**
> The Certificate Authority is stored in the active user's home directory. If you run `sudo mitm ...`, the CA will be created or loaded in the root user's home directory instead of your own.

That certificate authority is then used for any web requests.  That is, the proxy auto generates leaf certificates by the Certificate Authority based on the incomming (downstream) SNI.  Leaf certificates are saved to disk when generated, saved in a cache when requested, and populated into the cache when the proxy starts. 

This proxy can be helpful for decrypting TLS traffic if you can: 

1) Force the traffic to the listening port of the proxy
2) Install the Certificate Authority (`~/.mitm/ca.crt`) into the appropriate certificate store of the downstream client. 

There is an interesting feature (enabled by the `-W` flag to the `start` subcommand) that I'm calling [Wireshark Mode](#wireshark-mode).

Since Pingora natively supports WebSockets, this MITM proxy transparently handles WebSocket connections as well—no additional configuration required.

## Usage

### Basic Commands:

```
mitm        # same as `mitm start`
mitm start  # runs a https mitm server listening on localhost:6188
mitm start -c "path/to/upstream_ca_store.crt"   # Specify an upstream cert store 
mitm start -h # Shows all the options 
```

### mitm start help menu: 

```
Start the MITM Proxy

Usage: mitm start [OPTIONS]

Options:
  -p, --listening-port <LISTENING_PORT>
          Proxy listening port [default: 6188]
  -c, --ca-file <CA_FILE>
          Optional CA_File to use for the upstream TLS connection
  -i, --ignore-hostname-check
          Ignore the upstream hostname check, Default = False
  -k, --ignore-cert
          Ignore the upstream certificate, Default = False
  -s, --sni <SNI>
          Set the upstream SNI, otherwise uses the downstream SNI
  -u, --upstream <UPSTREAM>
          Specify a static origin for all upstream requests.
          When not supplied, it'll dynamically look up upstream by downstream SNI (or hostname if it is http).
          This is useful for testing or forcing all traffic to a single backend.
          Takes SocketAddrs, Eg: "127.0.0.1:443", "localhost:443"
  -t, --upstream-ssl-keys
          If this option is enabled, and the env variable SSLKEYLOGFILE is set, the upstream SSL keys will be written to that file
  -W, --wireshark-mode <WIRESHARK_MODE>
          Pass a port number that all traffic will be routed through on localhost for wireshark capture
  -h, --help
          Print help
```

### Sub Commands:

```
# Generates a Certificate Authority in $HOME/.mitm
mitm ca init
# Generate a leaf certificate signed by CA 
mitm ca sign -n "host.example.com" 
```

## Normal Proxy mode (mitm start)

A straight forward proxy service: 

```
+---------------------+     +-----------+     +------------------------+
| Client (Downstream) | --> |   MITM    | --> | HTTPS Server (Upstream)|
+---------------------+     +-----------+     +------------------------+
```

## Wireshark Mode 

A proxy composed of two components: 

```
+--------+     +-----------+     +-----------+     +--------------+
| Client | --> | Service A | --> | Service B | --> | HTTPS Server |
+--------+     +-----------+     +-----------+     +--------------+
```

Where the traffic between Service A and Service B traverses the loopback interface, unencrypted.  That is, open up wireshark on the loopback interface and use the filter `tcp.port == 4076`.  The port (4076) is passed with the `-W` flag.  Eg: 

```
mitm start -u "127.0.0.1:443" -i -k -W 4076
```

## TODO:
* Currently only linux is supported, think it would be trivial to get working on MacOS / Windows
* The cert returned is just the leaf certificate, and not a chain... should it be a chain?
* There's an assumption that Pingora will listen on localhost, add option to pass in an ip address (or maybe a socket addr)
* Make CA fields customizeable
* Make leaf certificates customizeable
* I started with rcgen, for cert generation, then found I wanted to use a OpenSSL/BoringSSL backend for pingora.  Should we generate certs using OpenSSL? 
* Make a stub version, where it's not a proxy at all but a webserver
* Do a full one-over on logging... Logging is inconsistent at the moment. 
* Probably should pass the ca around functions (currently is in the cache as just `ca`), right now it's being read from disk on every cert generation.
* Create Tests <- CA validity for leaf certs, connect connector to listner? 

## Maybe:
* Create a DNS server, that only responds with the address of the MITM proxy? 
* Create a local server, for responding to requests, calling this a stub above
* Create a web interface?

## Useful commands for testing: 

### Verifying a leaf certificate against a CA:

```
openssl verify -CAfile ca.crt example.sundquist.net.crt
```

### Test setup commands: 

```
cargo run -- ca sign -s "example.sundquist.net"
sudo gotestserver serve -s --cert "$HOME/.mitm/example.sundquist.net.crt" --key "$HOME/.mitm/example.sundquist.net.key"
cargo run -- start -c "$HOME/.mitm/ca.crt"
curl https://example.sundquist.net/request --connect-to ::127.0.0.1:6188 -svk 
```
