import subprocess 
import random

from sys import platform
from util import logger

def runRadamsa(fuzzer_input): # apply radaramsa for payload complexity
    if platform=='win32':
        return fuzzer_input.encode()

    seed = random.randint(0,128)
    radamsa = subprocess.Popen(['radamsa','--seed',str(seed)],stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    (fuzz_output ,err) = radamsa.communicate(fuzzer_input.encode('iso-8859-1'))

    if err:
        logger.printVerbose('[-] radamsa Error!! --- ',err)

    return fuzz_output

def makePayload(test,TOGGLE=0): # make Fuzz Packet. (pcap data + radramsa fuzz)
    if isinstance(test,bytes):    
        test = test.decode('iso-8859-1')
    

    if TOGGLE==0: # with dummy payload
        TOGGLE = 1
        logger.printVerbose('[*] Make Payload..!!')
        
        
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