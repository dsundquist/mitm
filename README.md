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
* Create a CLI, accepting arguements for the server
* Generate (or specify) a local certificate authority
* Generate leaf certificates using hostname provided by SNI / host, by that CA. 

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
curl https://example.sundquist.net --connect-to ::127.0.0.1:6188 -svk 
```

