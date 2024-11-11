from scapy.all import *

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