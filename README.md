# MITM 

A http(s) main-in-the-middle proxy, built using [Pingora Proxy](https://docs.rs/pingora). 

## Usage

### Basic Commands:

```
mitm       # same as `mitm start`
mitm start # runs a https mitm server listening on localhost:6188
```

### Sub Commands:

```
# Generates a Certificate Authority in $HOME/.mitm
mitm ca init
# Generate a leaf certificate signed by CA 
mitm ca gen-cert -n "host.example.com" 
```


## TODO:
* Create a CLI, accepting arguements for the server
* Generate (or specify) a local certificate authority
* Generate leaf certificates using hostname provided by SNI / host, by that CA. 

## Maybe:
* Create a DNS server, that only responds with the address of the MITM proxy? 
* Create a local server, for responding to requests
* Create a web interface
