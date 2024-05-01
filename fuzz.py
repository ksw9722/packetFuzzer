
import sys
import os
import socket
import random
import errno
import subprocess
import time
import queue
import argparse
import math
import struct

from scapy.all import *
from datetime import timedelta
from sys import platform

parser = argparse.ArgumentParser()
parser.add_argument("--ip",type=str,required=True,help="target ip address")
parser.add_argument("--port",type=int,required=True,help="target port")
parser.add_argument("--pcap",type=str,required=False,help="fuzzing corpus pcap file")
parser.add_argument("--corpus",type=str,required=False,help="fuzzing corpus path")
parser.add_argument("--protocol",type=str,required=True,help="target protocol")
parser.add_argument("-v",type=int,help="print debug data",default=0)
args = parser.parse_args()

testcase = []
ecount = 0
logQ = queue.Queue(maxsize = 100) # for packet logging
protocol = args.protocol

i = 0
VERBOSE = args.v
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
        if os.path.isdir(path+corpus):
            setCorpusUsingPath(path+corpus)
        else:
            f = open(path+corpus,'rb')
            contents = f.read()
            f.close()
            testcase.append(contents)
    print('[+] fuzzing corpus setting complete.')

def makeRandHTTPParam():
    a = 'a'*random.randint(0,128)
    b = 'b'*random.randint(0,128)
    c = 'c'*random.randint(0,128)

    result = 'a=%s&b=%s&c=%s'%(a,b,c)

    return result

def runRadamsa(fuzzer_input): # apply radaramsa for payload complexity
    if platform=='win32':
        return fuzzer_input.encode()

    seed = random.randint(0,128)
    radamsa = subprocess.Popen(['radamsa','--seed',str(seed)],stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    (fuzz_output ,err) = radamsa.communicate(fuzzer_input.encode('iso-8859-1'))

    if err:
        printVerbose('[-] radamsa Error!! --- ',err)

    return fuzz_output

def pcapParser(pcap,protocol): # parse Pcap and create Seed
    global testcase
    protocol = protocol.upper()

    if protocol == 'TCP':
        packetList = rdpcap(pcap)
        sessions = packetList.sessions()

        for session in sessions:

            for packet in sessions[session]:
                if packet.haslayer(Raw):
                    #print('-')
                    data = str(packet[Raw].load)
                    #print(str(data))

                    if len(data)<1:
                        continue

                    if data not in testcase:
                        testcase.append(data)
    
    else: # udp
        packetList = rdpcap(pcap)
        for packet in packetList:
            udp_packet = packet[UDP]
            data = str(udp_packet.payload)

            if len(data)<1:
                continue
            
            if data not in testcase:
                testcase.append(data)
        
def printVerbose(data):

    if VERBOSE!=0:
        print(data)

def makePayload(test,TOGGLE=0): # make Fuzz Packet. (pcap data + radramsa fuzz)
    if isinstance(test,bytes):    
        test = test.decode('iso-8859-1')
    

    if TOGGLE==0: # with dummy payload
        TOGGLE = 1
        printVerbose('[*] Make Payload..!!')
        
        
        if len(test.strip())==0:
            return ''
        #print('g')
        tmp = list(test)
        tlen = len(tmp)

        randchar = chr(random.randint(32,128))
        randpayload = randchar * random.randint(0,4000)
        randpos = random.randint(0,tlen)

        tval = random.randint(0,10)

        tmp.insert(randpos,randpayload)
        #print(tmp)
        payload = ''.join(tmp)

        return runRadamsa(payload)
    else: # only radamsa
        TOGGLE = 0
        return runRadamsa(test)

    # return payload

def printQ(q):
    si = q.qsize()
    f = open('result.txt','wb')

    for i in range(0,si):
        t = (q.get())
        printVerbose(t)
        printVerbose('============================================')
        f.write(t+b'fuzzsymb0l!@34')

    f.close()


def attack(protocol,TOGGLE): # send fuzzed packet to target.
    global i
    global logQ

    if protocol == 'TCP':

        attacksock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        attacksock.settimeout(5)
        attacksock.connect((args.ip,args.port))

        time.sleep(0.2)
        t = testcase[i%len(testcase)]
        #print(type(t))
        payload = makePayload(t,TOGGLE)
        
        if logQ.full():
            logQ.get()
        
        logQ.put(payload)
        
        if payload == '':
            i += 1
            return
                
        printVerbose(payload)
        attacksock.send(payload)

        tpayload = payload

    else : # case UDP
        
        attacksock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        attacksock.settimeout(5)
        
        time.sleep(0.2)
        t = testcase[i%len(testcase)]
        payload = makePayload(t)

        if logQ.full():
            logQ.get()
        
        logQ.put(payload)

        if payload == '':
            i +=1
            return 
        printVerbose(payload)
        attacksock.sendto(payload,(args.ip,args.port))

def main():
    global i
    print('[+] Fuzzing Start..!!!')
    print('[+] Fuzzer Pid : %d'%os.getpid())
    startTime = time.time()

    if args.pcap!=None:
        pcapParser(args.pcap,protocol) # TCP or UDP
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
            printQ(logQ)
            sys.exit(0)

        except socket.timeout:
            i +=1
            timecount+=1
            printVerbose('[*] TimeOut Occured..!!')
            

            if timecount == 3:
                print('[*] Fuzzing Exit...!! Timeout')
                endTime =time.time()
                elapsedTime = math.floor(endTime - startTime)
                elapsedTime = str(timedelta(seconds=elapsedTime))
                print('Elapsed Time for Fuzzing : %s'%elapsedTime)
                printQ(logQ)
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
                printQ(logQ)
                endTime =time.time()
                sys.exit()
    
main()