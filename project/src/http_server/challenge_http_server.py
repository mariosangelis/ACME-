from flask import Flask, redirect, url_for, request
import threading
import sys
from src.ACME_client.acme_client import lock,http_challenge_dict

global flask_app    
challenge_exiting_lock=threading.Lock()

class http_challenge_server:
    
    def __init__(self,record):
        global flask_app
        self.record=record
        self.thread=threading.Thread(target=self.http_challenge_server_thread_func)
        self.thread.daemon = True
    
    def http_challenge_server_thread_func(self):
        global flask_app
        flask_app=Flask(__name__)
        
        @flask_app.route("/.well-known/acme-challenge/<name>")
        def challenge_reply(name):
            global http_challenge_dict
            global lock
            global challenge_exiting_lock
            
            challenge_exiting_lock.acquire()
            #This is a request for HTTP challenge validation. Reply with the key_authorization_string for this domain.
            
            lock.acquire()
            token=http_challenge_dict[name]
            lock.release()
            challenge_exiting_lock.release()
            return token
        
        flask_app.run(debug=False,host=self.record, port=5002)
        
    def start(self):
        self.thread.start()
        
    def stop(self):
        global challenge_exiting_lock
        challenge_exiting_lock.acquire()
        return()
