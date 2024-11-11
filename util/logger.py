VERBOSE = False

def printVerbose(data):

    if VERBOSE:
        print(data)

def printQ(q):
    si = q.qsize()
    f = open('result.txt','wb')

    for i in range(0,si):
        t = (q.get())
        #printVerbose(t)
        #printVerbose('============================================')
        f.write(t+b'fuzzsymb0l!@34')

    f.close()