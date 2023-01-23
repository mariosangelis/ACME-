from flask import Flask, redirect, url_for, request
import threading
from threading import *
import os
import signal
import sys 

global flask_app   
termination_semaphore=Semaphore(0)

class shutdown_http_server:
    
    def __init__(self,record):
        global flask_app
        self.record=record
        self.thread=threading.Thread(target=self.shutdown_http_server_thread_func,args=())
        self.thread.daemon = True
    
    def shutdown_http_server_thread_func(self):
        global flask_app
        global termination_semaphore
        flask_app=Flask(__name__)
        
        @flask_app.route("/shutdown",methods = ['GET'])
        def challenge_reply():
            
            if request.method == 'GET':
                #Release the sempahore to wake up the main function.
                termination_semaphore.release()
                sys.exit(1)
        
        flask_app.run(debug=False,host=self.record, port=5003)
        
    def start(self):
        self.thread.start()
        
        
