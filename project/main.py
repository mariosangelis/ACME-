from src.http_server.challenge_http_server import *
from src.dns_server.dns_server import *
from src.ACME_client.acme_client import *
import click
from src.http_server.certificate_https_server import *
from src.http_server.shutdown_http_server import *
import time

@click.command()
@click.argument('dns01',required=False)
@click.option('--dir', required=True,type=click.STRING, help="This argument specifies the directory URL of the ACME server that should be used.")
@click.option('--record', required=True,type=click.STRING, help="This argument specifies the IPv4 address which must be returned by the DNS server for all A-record queries.")
@click.option('--domain', required=True,type=click.STRING, multiple=True, help="This argument specifies the domain for which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net.")
@click.option('--revoke',required=False,help="If present, the application should immediately revoke the certificate after obtaining it. In both cases, the application should start its HTTPS server and set it up to use the newly obtained certificate.",flag_value=True)

def main(dir,record,domain,revoke,dns01):
    
    if (dns01!="dns01" and dns01!="http01"):
        print("Valid options are dns01 and http01 for the dns-01 and http-01 challenges, respectively.")
        exit(1)
        
    global termination_semaphore
    
    #Create an HTTP challenge server object
    http_challenge=http_challenge_server(record)
    http_challenge.start()
    
    #Create a DNS server object
    dns_server=dns_server_class(domain,record)
    dns_server.start()

    #Start ACME client
    acme_client=ACME_CLIENT(dir,record,revoke,domain,dns01)
    ret=acme_client.acme_protocol_run()
    
    if(ret==-1):
        print("ACME client returned error. Aborting...")
        dns_server.stop()
        print("DNS server exited normally")
        
        http_challenge.stop()
        print("HTTP challenge server exited normally")
        return()
    
    #Create a certificate HTTP server
    http_server=certificate_http_server(record)
    http_server.start()

    #Create a certificate HTTP server
    shutdown_server=shutdown_http_server(record)
    shutdown_server.start()
    
    if(revoke):
        ret=acme_client.revoke_certificate()
        if(ret==-1):
            print("ACME revocation mechanism returned error. Aborting...")
            
            http_server.stop()
            print("HTTP certificate server exited normally")
            
            dns_server.stop()
            print("DNS server exited normally")
            
            http_challenge.stop()
            print("HTTP challenge server exited normally")
            
    
    #Block until user navigates to the url of the shutdown_http_server
    termination_semaphore.acquire()
    
    if(revoke==False):
        http_server.stop()
        print("HTTP certificate server exited normally")
        
        dns_server.stop()
        print("DNS server exited normally")
        
        http_challenge.stop()
        print("HTTP challenge server exited normally")
    return()
    
if __name__ == "__main__":
    
    main()
    
