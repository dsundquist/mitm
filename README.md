# MITM 

A http(s) main-in-the-middle proxy, built using [Pingora Proxy](https://docs.rs/pingora). 

## Usage

### Basic Commands:

```
mitm        # same as `mitm start`
mitm start  # runs a https mitm server listening on localhost:6188
mitm start -c "path/to/upstream_ca_store.crt"   # Specify an upstream cert store 
```

### Sub Commands:

```
# Generates a Certificate Authority in $HOME/.mitm
mitm ca init
# Generate a leaf certificate signed by CA 
mitm ca sign -n "host.example.com" 
```

## TODO:
* Right now, we always generate leaf certificates even if one is written to disk
* Create Cert Cache, fill cache with previously seen certificates (in ~/.mitm)
* Make CA fields customizeable
* Make Leaf Certificates Customizeable
* I started with rcgen, for cert generation, then found I wanted to use a OpenSSL/BoringSSL backend for pingora.  Should we generate certs using OpenSSL? 
* Make a stub version, where its not a proxy at all but a webserver
* Make a Wireshark mode.  Two proxies, with http in the middle for loopback sniffing. 
* To a full one over on logging... Logging is inconsistent at the moment. 
* Need to pass the ca around, right now its being read from disk on every cert generation.
* Create Tests <- CA validity for leaf certs, connect connector to listner? 

## Maybe:
* Create a DNS server, that only responds with the address of the MITM proxy? 
* Create a local server, for responding to requests
* Create a web interface

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

