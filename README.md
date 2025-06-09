# MITM 

A http(s) main-in-the-middle proxy, built using [Pingora Proxy](https://docs.rs/pingora). 

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

## TODO:
* The cert returned is just the leaf certificate, and not a chain... should it be a chain?
* Theres an assumption that pingora will listen on localhost, add option to pass in a ip address (or socket addr)
* Make CA fields customizeable
* Make Leaf Certificates Customizeable
* I started with rcgen, for cert generation, then found I wanted to use a OpenSSL/BoringSSL backend for pingora.  Should we generate certs using OpenSSL? 
* Make a stub version, where its not a proxy at all but a webserver
* Make a Wireshark mode.  Two proxies, with http in the middle for loopback sniffing. 
* Do a full one-over on logging... Logging is inconsistent at the moment. 
* Need to pass the ca around, right now its being read from disk on every cert generation.
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

