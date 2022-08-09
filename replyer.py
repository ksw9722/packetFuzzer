
import sys
import socket
import argparse
import time



parser = argparse.ArgumentParser()
parser.add_argument("--ip",type=str,required=True,help="target ip address")
parser.add_argument("--port",type=int,required=True,help="target port")
parser.add_argument("--file",type=str,required=True,help="log file")
parser.add_argument("--protocol",type=str,required=True,help="target protocol")
args = parser.parse_args()


protocol = args.protocol # SET TCP Protocol    
f = open(args.file,'rb')
c = f.read()
f.close()

c = c.split(b'fuzzsymb0l!@34')
#c.remove(b'')



leng = len(c)

print('[*] packet offset : %d-%d'%(0,leng-1))


s = input('reply start offset :')
e = input('reply end offset :')

s = int(s)
e = int(e)
#print 'c5 :',c[5]


for i in range(s,e+1):

    try:
    
        if protocol == 'TCP':
            attacksock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            attacksock.settimeout(5)
            attacksock.connect((args.ip,args.port))
            print('====================================================================')
            print(c[i])
            print('====================================================================')
            attacksock.send(c[i])
            dummy = attacksock.recv(4096)
        
        else: # case UDP
            attacksock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            attacksock.settimeout(5)
            print('====================================================================')
            print(c[i])
            print('====================================================================')
            attacksock.sendto(c[i],(args.ip,args.port))
            time.sleep(2)


    
    except Exception as e:
        print(e)
        print('====================================================================')
        print(c[i-1])
        print('====================================================================')
        print('====================================================================')
        print(c[i])
        print('====================================================================')
        sys.exit()



