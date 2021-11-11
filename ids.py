#!/usr/bin/python3
from scapy.all import *
from datetime import datetime
import sys
import time
import termcolor
import os
from playsound import playsound
import csv

class ids:
    TCP_flags = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
        }

    TCP_Ip_Counter = {}               #ip address  counter

    THRESH=1000               

    def sniffPackets(self,packet):
        if packet.haslayer(TCP):
            global sport
            global dport
            sport=packet.sport
            dport=packet.dport

        if packet.haslayer(IP):
        	global src_ip, dst_ip, pkt_id, protocol, checksum, dst_port, src_port
            src_ip=packet[IP].src
            dst_ip=packet[IP].dst
            pkt_id=packet[IP].id
            def ip_proto(pkt):
            	proto_field = pkt.get_field('proto')
            	return proto_field.i2s[pkt.proto]

            protocol = ip_proto(packet[IP])
            checksum=packet[IP].chksum
            dst_port=dport
            src_port=sport

            #csv header 
            header = ['Src IP', 'Src port', 'Dst IP', 'Dst port',  'Packet Id', 'Protocol', 'Checksum', 'Timestamp']
            data = []
            #write the data to a csv file
            with open('packets_csv.csv', 'wt', newline='') as f:
            	writer = csv.writer(f)
                #write header
                writer.writerow(header)

                #write data
            	for i in range(1000):
            		data.append(src_ip)
                	data.append(dst_port)
                	data.append(dst_ip)
                	data.append(src_port)
                	data.append(pkt_id)
                	data.append(protocol)
                	data.append(checksum)
                	data.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                	writer.writerow(data)
                	del data[:]
                	if i == 1000:
                    	f.close()
                    	break
                	else:
                		continue

            print("IP Packet: %s  ==>  %s, %s"%(src_ip,dst_ip,str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))) 

        if packet.haslayer(TCP):
            self.detect_TCPflooding(packet)
        else:
            pass


    def detect_TCPflooding(self,packet):
        if packet.haslayer(TCP):
            src_ip=packet[IP].src
            dst_ip=packet[IP].dst
            connection = src_ip + ':' + dst_ip

            if connection in type(self).TCP_Ip_Counter:
                type(self).TCP_Ip_Counter[connection] += 1
            else:
                type(self).TCP_Ip_Counter[connection] = 1

            for connection in type(self).TCP_Ip_Counter:
                pckts_sent = type(self).TCP_Ip_Counter[connection]
                if pckts_sent > type(self).THRESH:
                    src = connection.split(':')[0]
                    dst = connection.split(':')[1]
                    time.sleep(15)
                    for i in range(10):
                        print(termcolor.colored("TCP SYN Flooding detected from %s --> %s"%(src,dst), 'green'))    
                        time.sleep(4)                                        
                    
                    if pckts_sent > 1000:
                        if packet.haslayer(TCP):
                            sport=packet[TCP].sport
                            dport=packet[TCP].dport
                            for i in range(2550):
                                #capture the TCP flags send from attacker to victim 
                                flag = ([type(self).TCP_flags[x] for x in packet.sprintf('%TCP.flags%')])
                                if len(flag) == 2:
                                    flag_src = flag[0]
                                    flag_dst = flag[1]
                                    #a RST flag denotes the victim is resetting the connection
                                    if flag_src or flag_dst == 'RST':
                                        print(termcolor.colored(f'The victim server just flagged a RST flag', 'yellow'))
                                        break

                                    #FIN flag denoted notice by the victim to stop the connection process
                                    elif flag_src or flag_dst == 'FIN':
                                        print(termcolor.colored(f'The victim server just flagged a FIN flag', 'yellow'))
                                        break
                                    else:
                                        print(f'{flag_src} {flag_dst}')

                                #the attacker sends ACK flag but the server does not respond
                                else:
                                    if flag == 'RST':
                                     print(termcolor.colored(f'The victim server just flagged a RST flag', 'yellow'))
                                     break
                                    elif flag == 'FIN':
                                        print(termcolor.colored(f'The victim server just flagged a FIN flag', 'yellow'))
                                        break
                                    else:
                                        print(termcolor.colored(f'The victim server is becoming unresponsive', 'yellow'))
                                        #time.sleep(0.6)

                            print('\n')
                            for i in range(4):
                                print(termcolor.colored('DDoS attack happening now', 'red'))
                                playsound('alert.mp3')
                                time.sleep(10)
                            sys.exit()


if __name__ == '__main__':
    print(termcolor.colored("*****Network Intrusion Detection System*****", 'yellow'))
    print(termcolor.colored('This program is designed by J87034 & all rights reserved', 'yellow'))
    print(termcolor.colored('The program uses Scapy to sniff TCP packets, detect TCP SYN flooding, and reports DDoS attack', 'yellow'))  
    print(termcolor.colored('Check whether you have all the requuired modules by running the command below:', 'yellow'))
    print(termcolor.colored('<pip install -r requirements.txt> the requirements.txt file should be in the same folder as the program', 'yellow'))
    print(termcolor.colored('press CTRL C to exit the program', 'yellow'))
    time.sleep(5)
    sniff(filter="ip",iface="eth0",prn=ids().sniffPackets)
