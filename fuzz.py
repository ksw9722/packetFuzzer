
import sys
import os
import socket

import time
import queue
import argparse
import math


from scapy.all import *
from datetime import timedelta
from payload import radamsa
from util import logger
from util import parser

parser = argparse.ArgumentParser()
parser.add_argument("--ip",type=str,required=True,help="target ip address")
parser.add_argument("--port",type=int,required=True,help="target port")
parser.add_argument("--pcap",type=str,required=False,help="fuzzing corpus pcap file")
parser.add_argument("--corpus",type=str,required=False,help="fuzzing corpus path")
parser.add_argument("--protocol",type=str,required=True,help="target protocol")
parser.add_argument("-v",help="print debug data",action="store_true")
parser.add_argument("-s",help="sniper mode. fuzzing only specific data / area.",action="store_true")
parser.add_argument("-sp",help="sniper mode payload",type=str)
args = parser.parse_args()


testcase = []
ecount = 0
logQ = queue.Queue(maxsize = 100) # for packet logging
protocol = args.protocol
protocol = protocol.upper()

i = 0
logger.VERBOSE = args.v
#VERBOSE = True
WEB = 0
DNS = 0
UPNP = 0
TELNET = 0
FTP = 0

def setCorpusUsingPath(path):
    print('[+] set fuzzing corpus...')
    global testcase
    corpusList = os.listdir(path)

    for corpus in corpusList:
        if not os.path.isdir(path+corpus):
            f = open(path+corpus,'rb')
            contents = f.read()
            f.close()
            testcase.append(contents)
    print('[+] fuzzing corpus setting complete.')
    print(testcase)

def attack(protocol,TOGGLE): # send fuzzed packet to target.
    global i
    global logQ

    if protocol == 'TCP':

        attacksock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        attacksock.settimeout(3)
        attacksock.connect((args.ip,args.port))

        time.sleep(0.2)
        t = testcase[i%len(testcase)]
        #print(type(t))
        payload = radamsa.makePayload(t,TOGGLE)
        
        if logQ.full():
            logQ.get()
        
        logQ.put(payload)
        
        if payload == '':
            i += 1
            return
                
        logger.printVerbose(payload)
        attacksock.send(payload)

        tpayload = payload

    else : # case UDP
        
        attacksock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        attacksock.settimeout(5)
        
        time.sleep(0.2)
        t = testcase[i%len(testcase)]
        payload = radamsa.makePayload(t)

        if logQ.full():
            logQ.get()
        
        logQ.put(payload)

        if payload == '':
            i +=1
            return 
        logger.printVerbose(payload)
        attacksock.sendto(payload,(args.ip,args.port))

def main():
    global i
    print('[+] Fuzzing Start..!!!')
    print('[+] Fuzzer Pid : %d'%os.getpid())
    startTime = time.time()

    if args.pcap!=None:
        parser.pcapParser(args.pcap,protocol) # TCP or UDP
        #print(testcase)
        
    elif args.corpus!=None:
        setCorpusUsingPath(args.corpus)
    else:
        print('[-] set --corpus or --pcap')
        parser.print_help(sys.stderr)
        sys.exit(0)
    ecount = 0
    timecount = 0

    while True:
        try:
            while True:
                if protocol == 'TCP':
                    attack('TCP',0)
                    attack('TCP',1)
                else:
                    attack('UDP',0)
                    attack('UDP',1)
                i +=1
                
        except KeyboardInterrupt:
            print('[*] Fuzzing Exit...!! Keyboard Interrupt')
            endTime =time.time()
            elapsedTime = math.floor(endTime - startTime)
            elapsedTime = str(timedelta(seconds=elapsedTime))
            print('Elapsed Time for Fuzzing : %s'%elapsedTime)
            logger.printQ(logQ)
            sys.exit(0)

        except socket.timeout:
            i +=1
            timecount+=1
            logger.printVerbose('[*] TimeOut Occured..!!')
            

            if timecount == 3:
                print('[*] Fuzzing Exit...!! Timeout')
                endTime =time.time()
                elapsedTime = math.floor(endTime - startTime)
                elapsedTime = str(timedelta(seconds=elapsedTime))
                print('Elapsed Time for Fuzzing : %s'%elapsedTime)
                logger.printQ(logQ)
                endTime =time.time()
                sys.exit()
            continue
    

        except Exception as e:
            ecount +=1
            print('[-] Error :'+str(e))

            if ecount == 100000:
                print('[*] Fuzzing Exit...!!error occured')
                endTime =time.time()
                elapsedTime = math.floor(endTime - startTime)
                elapsedTime = str(timedelta(seconds=elapsedTime))
                print('Elapsed Time for Fuzzing : %s'%elapsedTime)
                logger.printQ(logQ)
                endTime =time.time()
                sys.exit()
    
main()