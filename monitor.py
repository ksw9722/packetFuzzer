import gdb
import sys
import os


pid = 4601# fuzzer pid 


print('[+] Monitoring start for pid : %d'%pid)

gdb.execute("c") #run gdb
os.system("kill -2 %d"%pid) # intrrupt occured.
print('[+] interrupt are occured!')

