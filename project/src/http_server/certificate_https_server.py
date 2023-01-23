from flask import Flask, redirect, url_for, request
import threading
import sys

global flask_app

class certificate_http_server:
    
    def __init__(self,record):
        global flask_app
        self.record=record
        self.certificate=self.read_certificate()
        self.thread = threading.Thread(target=self.certificate_http_server_thread_func,args=())
        self.thread.daemon = True
    
    def read_certificate(self):
        
        try:
            f=open("../cert/cert.pem", 'r')
            certificate=f.read()
            f.close()
            
        except IOError:
            print("Failure in reading I/O")
        
        return certificate
    
    def certificate_http_server_thread_func(self):
        global flask_app
        flask_app=Flask(__name__)
        
        @flask_app.route("/")
        def challenge_reply():
            return self.certificate
        
        #The client will establish a secure TLS connection with this certificate server. Thus, we should provide the path to the certificate and to the private key to sign the certificate.
        #The certificate should include the public key so that the client to be able to validate this signature.
        flask_app.run(debug=False,host=self.record, ssl_context=("../cert/cert.pem","../priv/priv.pem"),port=5001)
        
    def start(self):
        self.thread.start()

    def stop(self):
        return()
        
        
        
