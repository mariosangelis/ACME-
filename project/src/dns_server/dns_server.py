from dnslib import *
from dnslib.server import DNSServer
import socketserver
import threading
import sys
from src.ACME_client.acme_client import lock,dns_challenge_dict

domain_list=[]
dns_exiting_lock=threading.Lock()

class BaseResolver(object):
    
    def resolve(self,request,handler):

        global domain_list
        global dns_challenge_dict
        global lock
        qname = request.q.qname
        qn = str(qname)
        qtype = request.q.qtype
        qt = QTYPE[qtype]
        
        #This is a TXT record for DNS challenge validation. Reply with the key_authorization_string for this domain.
        if(qtype==16):
            name=str(qname)
            name=name[len("_acme-challenge."):len(name)-1]
            lock.acquire()
            reply=DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q,a=RR(rname=qname,rtype=16,rdata=TXT(dns_challenge_dict[name])))
            lock.release()
            
        elif(qtype==1 or qtype==28):
            #This is an A DNS record. Reply with the IP of this domain.
            for domain in domain_list:
                if(qname==domain["domain_name"]):
                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q,a=RR(rname=qname,rdata=A(domain["ip"])))
                    break
        else:
            return None
        
        return reply

class DNSHandler(socketserver.BaseRequestHandler):

    udplen = 0 

    def handle(self):
        global dns_exiting_lock
        dns_exiting_lock.acquire()
        self.protocol = 'udp'
        data,connection = self.request
        rdata = self.get_reply(data)
        
        connection.sendto(rdata,self.client_address)
        dns_exiting_lock.release()

    def get_reply(self,data):
        request = DNSRecord.parse(data)
        
        resolver = self.server.resolver
        reply = resolver.resolve(request,self)

        rdata = reply.pack()
        if self.udplen and len(rdata) > self.udplen:
            truncated_reply = reply.truncate()
            rdata = truncated_reply.pack()

        return rdata


class dns_server_class:
    
    def __init__(self,domain,record):
        global domain_list
        self.server=DNSServer(resolver=BaseResolver(),address=record,port=10053)
        self.thread = threading.Thread(target=self.server.server.serve_forever)
        self.thread.daemon = True
        
        for i in range(0,len(domain)):
            domain_list.append({"domain_name":domain[i],"ip":record})

    def start(self):
        self.thread.start()

    def stop(self):
        global dns_exiting_lock
        dns_exiting_lock.acquire()
        self.server.stop()
        return()
        





