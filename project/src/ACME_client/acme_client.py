import requests
import json
import Crypto
import os
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.number import long_to_bytes
import time
from src.http_server.challenge_http_server import *
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

lock = threading.Lock()
http_challenge_dict={}
dns_challenge_dict={}

class ACME_CLIENT:
    
    def __init__(self,dir,record,revoke,domain,dns01):
        
        self.record=record
        self.revoke=revoke
        self.domain=domain
        self.rsa_key=""
        self.kid=""
        self.dir=dir
        
        if(dir[-4:]=="/dir"):
            self.dir=dir[:-4]
        
        if (dns01=="dns01"):
            self.dns_active=True
        elif (dns01=="http01"):
            self.dns_active=False
    
    def generate_key_for_certificate(self):
        
        if(os.path.exists("../priv")==False):
            os.makedirs("../priv")
        
        try:
            f=open("../priv/priv.pem", 'wb')
            
            #Write the private key in a file located at /priv/priv.pem using PEM encoding
            rsa_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
            
            f.write(rsa_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption(),))
            f.close()
            
        except IOError:
            print("Failure in reading I/O")
            
        return rsa_key
    
    #This function generates a CSR for the ACME client.
    def generate_csr(self):
        
        #Create a new key pair for the certificate. Sign the CSR with the private key. The CSR contains the public key that the certificate will include.
        key = self.generate_key_for_certificate()
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ETH")
        ])).add_extension(x509.SubjectAlternativeName(
        [
            # Describe for what domains we want this certificate for. The CSR MUST indicate the exact same set of requested identifiers as the initial newOrder request.
            x509.DNSName(domain) for domain in self.domain
        ]),critical=False,).sign(key, hashes.SHA256(), backend=default_backend())
        
        return csr
        
    #This finction removes the trailing = characters
    def remove_trailing_padding(self,input_string):
        
        while(input_string[-1:]=='='):
            input_string=input_string[:-1]
        
        return input_string

    #This function is used in order to get a fresh nonce form the ACME server
    def get_new_nonce(self):
        
        server_reply=None
        try:
            server_reply = requests.head(self.dir+"/nonce-plz",verify="pebble.minica.pem")
        except:
            return(-1)
    
        if(server_reply.status_code!=201 and server_reply.status_code!=200):
            print("An error has occured. Server response: ",server_reply.reason," status code: ",server_reply.status_code)
            print(server_reply.text)
            return(-1)
        
        server_nonce=server_reply.headers['Replay-Nonce']
        
        return(server_nonce)

    #This function is used to send all the requests to the ACME server over HTTPS
    def send_signed_request(self,url,payload,kid=None,base_64_e=None,base_64_n=None):
        
        #Get a fresh nonce from server
        server_nonce = self.get_new_nonce()
        if(server_nonce==-1):
            return(-1)
        
        if(kid==None):
            #jwk dictionary is used when creating an ACME account
            jwk={"kty":"RSA","n":base_64_n,"e":base_64_e}
            header={"alg": "RS256", "jwk": jwk, "nonce": server_nonce,"url": url}
        else:
            header={"alg": "RS256", "kid": kid, "nonce": server_nonce,"url": url}
        
        enc_header = base64.urlsafe_b64encode(json.dumps(header,separators=(',', ':')).encode("utf8")).decode("utf8")
        enc_header=self.remove_trailing_padding(enc_header)
        
        if(payload==None):
            enc_payload=base64.urlsafe_b64encode(json.dumps({}).encode("utf8")).decode("utf8")
        elif(payload==""):
            enc_payload=base64.urlsafe_b64encode("".encode("utf8")).decode("utf8")
        else:
            enc_payload = base64.urlsafe_b64encode(json.dumps(payload,separators=(',', ':')).encode("utf8")).decode("utf8")
                
        enc_payload=self.remove_trailing_padding(enc_payload)
        
        enc = "{0}.{1}".format(enc_header, enc_payload)
        enc=enc.encode("utf8")

        signer = PKCS1_v1_5.new(self.rsa_key)
        h = SHA256.new(enc)
        signature = signer.sign(h)
            
        signature=base64.urlsafe_b64encode(signature).decode("utf8")
        signature=self.remove_trailing_padding(signature)

        json_object={"protected": enc_header, "payload": enc_payload, "signature": signature}
            
        #Send a request to the server in order to create a new account
        try:
            server_reply=requests.post(url,json=json_object,headers={"Content-Type": "application/jose+json"},verify="pebble.minica.pem")
        except:
            return(-1)
        
        if(server_reply.status_code!=201 and server_reply.status_code!=200):
            print("An error has occured. Server response: ",server_reply.reason," status code: ",server_reply.status_code)
            print(server_reply.text)
            return(-1)
        
        return(server_reply)
    
    #Write the certificate in a file located into /cert/cert.pem 
    def write_certificate(self,certificate):
        
        if(os.path.exists("../cert")==False):
            os.makedirs("../cert")
        
        try:
            f=open("../cert/cert.pem", 'w')
            f.write(certificate)
            f.close()
            
        except IOError:
            print("Failure in reading I/O")
            
    def revoke_certificate(self):
        
        try:
            f=open("../cert/cert.pem", "rb")
            
        except IOError:
            print("Failure in reading I/O")
        
        certificate = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
        certificate=certificate.public_bytes(encoding=serialization.Encoding.DER)
        
        body={"certificate":base64.urlsafe_b64encode(certificate).decode("utf8"),"reason":4}
        
        #Send a revocation request to the ACME server
        server_reply=self.send_signed_request(self.dir+"/revoke-cert",body,kid=self.kid)
        if(server_reply==-1 or server_reply.status_code!=200):
            return(-1)
        
        return(1)
        
    #This function contains all the functionality of the ACME protocol
    def acme_protocol_run(self):
        
        global http_challenge_dict
        global lock
        
        #Get ACME server's directory structure.
        #The file pebble.minica.pem is the certificate of the Certification Authority that signs the certificate of the ACME server. The ACME client should have this certificate
        #in order to trust the CA that signs the certificate of the ACME server so that a secure TLS connection to be established.
        try:
            server_reply = requests.get(self.dir+"/dir",verify="pebble.minica.pem")
        except:
            return(-1)
        
        if(server_reply.status_code!=201 and server_reply.status_code!=200):
            print("An error has occured. Server response: ",server_reply.reason," status code: ",server_reply.status_code)
            print(server_reply.text)
            return(-1)
        
        acme_server_hierarchy=server_reply.content.decode(server_reply.encoding)
        
        #----------------------------------------------------------------------Create an account--------------------------------------------------------------------

        #Generate a RSA key pair
        self.rsa_key = RSA.generate(2048)
        
        #Convert n from integer to bytes with length equal to math.ceil( rsa_key.e.bit_length() / 8)
        base_64_n=base64.urlsafe_b64encode(long_to_bytes(self.rsa_key.n)).decode("utf8")
        base_64_n=self.remove_trailing_padding(base_64_n)
        
        #Convert e from integer to bytes with length equal to math.ceil( rsa_key.e.bit_length() / 8)
        base_64_e=base64.urlsafe_b64encode(long_to_bytes(self.rsa_key.e)).decode("utf8")
        base_64_e=self.remove_trailing_padding(base_64_e)

        body = {"termsOfServiceAgreed": True, "contact": []}
        #A client creates a new account with the server by sending a POST request to the server's newAccount URL.  
        server_reply=self.send_signed_request(self.dir+"/sign-me-up",body,base_64_e=base_64_e,base_64_n=base_64_n)
        if(server_reply==-1):
            return(-1)
        
        print("Account created")
        #----------------------------------------------------------------------Applying for Certificate Issuance-----------------------------------------------------
        
        self.kid=server_reply.headers['Location']
        jwk={"kty":"RSA","n":base_64_n,"e":base_64_e}    
        accountkey_json = json.dumps(jwk,sort_keys=True,separators=(',', ':'))
        
        thumbprint=base64.urlsafe_b64encode(SHA256.new(accountkey_json.encode('utf8')).digest()).decode("utf8")
        thumbprint=self.remove_trailing_padding(thumbprint)
        
        identifiers=[]
        
        for i in range(0,len(self.domain)):
            item={"type":"dns","value":self.domain[i]}
            identifiers.append(item)
                
        body = {"identifiers":identifiers}
        
        '''The client begins the certificate issuance process by sending a POST request to the server's newOrder resource.  The body of the POST is a
        JWS object whose JSON payload is a subset of the order object containing identifiers that is an array of identifier objects that the client wishes to submit an order for.'''
        server_reply=self.send_signed_request(self.dir+"/order-plz",body,kid=self.kid)
        if(server_reply==-1):
            return(-1)
        print("Order sent successfully to the server")
        #print(server_reply.text)
        
        '''The order object returned by the server represents a promise that if the client fulfills the server's requirements before the "expires" time, then the server will be willing to finalize the order upon request and issue the requested certificate.  In the order object, any authorization referenced in the "authorizations" array whose status is "pending" represents an authorization transaction that the client must complete before the server will issue the certificate'''
        order_object=json.loads(server_reply.text)
        order_url=server_reply.headers["Location"]
        
        
        for i in range(0,len(order_object['authorizations'])):
            
            #Ask for an authorization object from each authorization url
            server_reply=self.send_signed_request(order_object['authorizations'][i],"",kid=self.kid)
            if(server_reply==-1):
                return(-1)
            
            '''An ACME authorization object represents a server's authorization for an account to represent an identifier.  In addition to the identifier, an authorization includes several metadata fields, such as the status of the authorization (e.g., "pending", "valid", or "revoked") and which challenges were used to validate possession of the identifier.'''
            #print(server_reply.text)
            authorization_object=json.loads(server_reply.text)
            
            if(authorization_object['status'] == "valid"):
                print("Already verified, skipping...")
            else:
                domain_to_authorize = authorization_object['identifier']['value']
                challenge_list=authorization_object['challenges']
                
                for challenge in challenge_list:
                    if(self.dns_active==True and challenge['type']=="dns-01" and challenge['status']=="pending"):
                        break
                    elif(self.dns_active==False and challenge['type']=="http-01" and challenge['status']=="pending"):
                        break
                
                key_authorization_string=challenge['token']+'.'+thumbprint
                
                #Update the dns challenge dictionary as well as the http challenge dictionary
                lock.acquire()
                http_challenge_dict.update({challenge['token']:key_authorization_string})
                dns_token=base64.urlsafe_b64encode(SHA256.new(key_authorization_string.encode("utf8")).digest()).decode("utf8")
                dns_token=self.remove_trailing_padding(dns_token)
                dns_challenge_dict.update({domain_to_authorize:dns_token})
                lock.release()
                
                '''To prove control of the identifier and receive authorization, the client needs to provision the required challenge response based on the challenge type and indicate to the server that it is ready for the challenge validation to be attempted. The client indicates to the server that it is ready for the challenge validation by sending an empty JSON body ("{}") carried in a POST request to the challenge URL (not the authorization URL).'''
                server_reply=self.send_signed_request(challenge['url'],None,kid=self.kid)
                if(server_reply==-1):
                    return(-1)
                
                '''Usually, the validation process will take some time, so the client will need to poll the authorization resource to see when it is finalized. To check on the status of an authorization, the client sends a POST-as-GET request to the authorization URL, and the server responds with the current authorization object. '''
                while(1):
                    time.sleep(1)
                    server_reply=self.send_signed_request(order_object['authorizations'][i],"",kid=self.kid)
                    if(server_reply==-1):
                        return(-1)
                    
                    challenge_reply=json.loads(server_reply.text)
                    
                    if(challenge_reply['status']=="valid"):
                        break
                    
                    if(challenge_reply['status']=="invalid"):
                        print("ACME server cannot validate. Aborting")
                        return(-1)
        
        #Once the client believes it has fulfilled the server's requirements, it should send a POST request to the order resource's finalize URL. The POST body MUST include a CSR
        body = {"csr":base64.urlsafe_b64encode(self.generate_csr().public_bytes(encoding=serialization.Encoding.DER)).decode("utf8")}
        server_reply=self.send_signed_request(order_object['finalize'],body,kid=self.kid)        
        if(server_reply==-1):
            return(-1)
            
        while(1):
            #The client should then send a POST-as-GET request to the order resource to obtain its current state.  The status of the order will indicate what action the client should take.
            server_reply=self.send_signed_request(order_url,"",kid=self.kid)        
            if(server_reply==-1):
                return(-1)
                
            csr_reply=json.loads(server_reply.text)
            if(csr_reply["status"]=="valid"):
                break
            time.sleep(1)
        
        #To download the issued certificate, the client simply sends a POST-as-GET request to the certificate URL.
        server_reply=self.send_signed_request(csr_reply["certificate"],"",kid=self.kid)        
        if(server_reply==-1):
            return(-1)
        
        self.write_certificate(server_reply.text)
        
        
