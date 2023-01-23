# ACME Protocol

This is the first project of Network Security Course (Fall Semester 2022) taught at ETH Zurich. The Task was to implement an ACMEv2 client from scratch using only standard libraries. The ACME client communicates with an already existing ACME server (or the Pebble testing server) in order to obtain and manage SSL certificates.

## Description
Public Key Infrastructures (PKIs) using X.509 certificates are used for many purposes, the most significant of which is the authentication of domain names. Certificate Authorities (CAs) are trusted to verify that an applicant for a certificate legitimately represents the domain name(s) in the certificate. Traditionally, this verification is done through various ad-hoc methods.
The Automatic Certificate Management Environment (ACME) protocol aims to facilitate the automation of certificate issuance by creating a standardized and machine-friendly protocol for certificate management.
More information about ACME and relevant background can be found in RFC8555.

## Application Components

* ACME client: An ACME client which can interact with a standard-conforming ACME server.

* DNS server: A DNS server which resolves the DNS queries of the ACME server.

* Challenge HTTP server: An HTTP server to respond to http-01 queries of the ACME server.

* Certificate HTTPS server: An HTTPS server which uses a certificate obtained by the ACME client.

* Shutdown HTTP server:  An HTTP server to receive a shutdown signal.

## Functionality

* Use the ACME protocol to request and obtain certificates using the dns-01 and http-01 challenge,
* Request and obtain certificates which contain aliases,
* Request and obtain certificates with wildcard domain names, and
* Revoke certificates after they have been issued by the ACME server.

## Run
* Navigate to pebble directory and open docker-compose.yml file
* Change the following command by providing the ip of the host machine
  command: `pebble -config /test/config/pebble-config.json -strict -dnsserver 10.4.11.209:10053`
* `docker compose up -d` in order to start pebble
* Example run: 
`./run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch`
`./run http01 --dir https://127.0.0.1:14000 --record 10.4.11.209 --domain netsec.ethz.ch mangelis.ethz.ch --revoke`
`./run dns01 --dir https://127.0.0.1:14000 --record 10.4.11.209 --domain *.exam`

## Arguments
### Positional arguments:

* `Challenge` type (required, `{dns01 | http01}`) indicates which ACME challenge type the client should perform. Valid options are dns01 and http01 for the `dns-01` and `http-01` challenges, respectively.

### Keyword arguments:

* `--dir DIR_URL` (required) `DIR_URL` is the directory URL of the ACME server that should be used.

* `--record IPv4_ADDRESS` (required) `IPv4_ADDRESS` is the IPv4 address which must be returned by your DNS server for all A-record queries.

* `--domain DOMAIN` (required, multiple) `DOMAIN` is the domain for which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net.

* `--revoke` (optional) If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.
