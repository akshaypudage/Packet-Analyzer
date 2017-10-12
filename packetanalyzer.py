'''
packetanalyzer.py by Akshay Pudage 
'''

import binascii
import socket
import sys

def processIPHeader(hexPacket):
    '''
    This function takes in the IP header in hex and processes it
    :param hexPacket: packet string in hex
    :return:
    '''
    print("IP:  ----IP Header----")
    print("IP:  ")

    print('IP:  Version= ' + str(hexPacket[28:29].decode("utf-8")))
    ipHeaderLength = int(hexPacket[29:30]) * 4
    print('IP:  Header length= ' + str(ipHeaderLength) + " bytes")
    print('IP:  Type of service= 0x' + str(hexPacket[30:32].decode("utf-8")))

    typeOfService = bin(int(hexPacket[30:32],16))
    typeOfService = typeOfService[2:].zfill(8)

    bit3Status = "normal delay"
    bit4Status = "normal throughput"
    bit5Status = "normal reliability"

    if typeOfService[3] == "1" :
        bit3Status = "low delay"
    if typeOfService[4] == "1" :
        bit4Status = "high throughput"
    if typeOfService[5] == "1":
        bit5Status = "high reliability"

    print("IP:  \txxx. .... = 0 (precedence)")
    print("IP: \t..." +str(typeOfService[3]) +" .... = " +bit3Status)
    print("IP: \t.... " + str(typeOfService[4]) + "... = " + bit4Status)
    print("IP: \t.... ." + str(typeOfService[5]) + ".. = " + bit5Status)

    totalLength = int(hexPacket[32:36].decode("utf-8"), 16)
    print('IP:  Total length= ' + str(totalLength) + ' bytes')

    print('IP:  Identification= ' + str(int(hexPacket[36:40].decode("utf-8"), 16)))

    flagsIP = hexPacket[40:44]

    bits = bin(int(flagsIP, 16))
    bits = bits[2:].zfill(16)
    flagbits = bits[0:3]

    print("IP:  Flags= " +hex(int(flagbits,2)))

    if flagbits[1] == "1":
        fragmentStatus = "Don't Fragment (DF)"
    else:
        fragmentStatus = "Fragment"

    if flagbits[2] == "1":
        moreFragmentsStatus = "More Fragments (MF)"
    else:
        moreFragmentsStatus = "Last Fragment"
    print("IP:  \t." +flagbits[1] +".." +" .... " +fragmentStatus)
    print("IP:  \t.." +flagbits[2] +"." +" .... " +moreFragmentsStatus)


    fragmentOffset = int(bits[3:].zfill(16),2)
    print("IP:  Fragment offset= " +str(fragmentOffset) +" bytes")

    print('IP:  Time to live= ' + str(int(hexPacket[44:46].decode("utf-8"), 16)) + ' seconds/hops')

    protocol = int(hexPacket[46:48].decode("utf-8"), 16)

    if protocol == 6:
        protocolStatus = " (TCP)"
    if protocol == 1:
        protocolStatus = " (ICMP)"
    if protocol == 17:
        protocolStatus = " (UDP)"
    print('IP:  Protocol= ' + str(protocol) +protocolStatus)

    print('IP:  Header checksum= ' + hexPacket[48:52].decode("utf-8"))

    sourceIPAddr = str(int(hexPacket[52:54].decode("utf-8"), 16)) + "." + str(int(hexPacket[54:56].decode("utf-8"), 16)) + "." + str(
            int(hexPacket[56:58].decode("utf-8"), 16)) + "." + str(int(hexPacket[58:60].decode("utf-8"), 16))

    destinationIPAddr = str(int(hexPacket[60:62].decode("utf-8"), 16)) + "." + str(
        int(hexPacket[62:64].decode("utf-8"), 16)) + "." + str(int(hexPacket[64:66].decode("utf-8"), 16)) + "." + str(
        int(hexPacket[66:68].decode("utf-8"), 16))

    sourceHostName,x,y = socket.gethostbyaddr(sourceIPAddr)
    destinationHostName,x,y = socket.gethostbyaddr(destinationIPAddr)

    print(
        'IP:  Source= ' + sourceIPAddr +", " +sourceHostName)
    print('IP:  Destination= ' + destinationIPAddr +", " +destinationHostName)
    print("IP:  No options")
    print("IP:  ")
    if protocol == 6:
        processTCPHeader(hexPacket)
    elif protocol == 1:
        processICMPHeader(hexPacket)
    elif protocol == 17:
        processUDPHeader(hexPacket)


def processTCPHeader(hexPacket):
    '''
    This function takes in the TCP header in hex and processes it
    :param hexPacket:
    :return:
    '''
    ####TCP###########3
    print("TCP:  ----TCP Header----")
    print("TCP:  ")
    print('TCP:  Source Port= ' + str(int(hexPacket[68:72].decode("utf-8"), 16)))
    print('TCP:  Destination Port= ' + str(int(hexPacket[72:76].decode("utf-8"), 16)))
    print('TCP:  Sequence Number= ' + str(int(hexPacket[76:84].decode("utf-8"), 16)))
    print('TCP:  Acknowledgement Number= ' + str(int(hexPacket[84:92].decode("utf-8"), 16)))
    print('TCP:  Data offset= ' + str(int(hexPacket[92:93].decode("utf-8"), 16) * 4) + " bytes")

    reservedAndFlags = bin(int(hexPacket[93:96],16))
    reservedAndFlags = reservedAndFlags[2:].zfill(12)
    #print(reservedAndFlags)
    flagBits = reservedAndFlags[5:]
    print("TCP:  Flags= " +str(hex(int(flagBits,2))))
    bit1Status = "No urgent pointer"
    bit2Status = "No acknowledgement"
    bit3Status = "No push"
    bit4Status = "No reset"
    bit5Status = "No Syn"
    bit6Status = "No Fin"

    if flagBits[0] == "1":
        bit1Status = "Urgent pointer"
    if flagBits[1] == "1":
        bit2Status = "Acknowledgement"
    if flagBits[2] == "1":
        bit3Status = "Push"
    if flagBits[3] == "1":
        bit4Status = "Reset"
    if flagBits[4] == "1":
        bit5Status = "Syn"
    if flagBits[5] == "1":
        bit6Status = "Fin"

    print("TCP:  \t.." + flagBits[0] + "." + " .... = " + bit1Status)
    print("TCP:  \t..." + flagBits[1] + " .... = " + bit2Status)
    print("TCP:  \t.... " + flagBits[2]  + "... = " + bit3Status)
    print("TCP:  \t.... ." + flagBits[3]  + ".. = " + bit4Status)
    print("TCP:  \t.... .." + flagBits[4] + ". = " + bit5Status)
    print("TCP:  \t.... ..."  + flagBits[5] + " = " + bit6Status)


    print('TCP:  Window= ' + str(hexPacket[96:100].decode("utf-8")))
    print('TCP:  Checksum= 0x' + hexPacket[100:104].decode("utf-8"))
    print('TCP:  Urgent pointer= ' + str(int(hexPacket[104:108].decode("utf-8"), 16)))
    print("TCP:  No options")
    print("TCP:  ")

    data = hexPacket[108:]

    print("TCP:  Data: (first 64 bytes)")
    for i in range(32,160,32):
        if len(data) <= 0:
            break
        dataToConvert = data[:32]
        asciiData = convertToAscii(dataToConvert)
        toPrint = formatString(dataToConvert.decode("utf-8"))
        print("TCP:  " +toPrint +"\t" '"' +str(asciiData) +'"')
        data = data[i:]

    print("TCP:  ")


def formatString(text):
    '''
    This method formats the string passed to it to be represented in the form of 2 bytes
    :param text: text to be formatted
    :return:
    '''
    formattedString = ""
    while len(text) >=1:
        formattedString += text[:4] +" "
        text = text[4:]
    return formattedString

def convertToAscii(data):
    '''
    This method converts the hex data to ASCII
    :param data: data to be converted to ASCII
    :return:
    '''
    output =""
    while len(data) >= 2:
        hex = data[:2]
        if int(hex,16) >= 33 and int(hex,16) <=126:
            output += binascii.unhexlify(hex).decode("utf-8")
        else:
            output += "."
        data = data[2:]
    return output



def processICMPHeader(hexPacket):
    '''
    This function takes in the ICMP header in hex and processes it
    :param hexPacket: packet header to be processed
    :return:
    '''
    print("ICMP:  ----ICMP Header----")
    print("ICMP:  ")
    print('ICMP:  Type= ' + str(int(hexPacket[68:70].decode("utf-8"),16)))
    print('ICMP:  Code= ' + str(int(hexPacket[70:72].decode("utf-8"), 16)))
    print('ICMP:  Checksum= ' + str(hexPacket[72:76].decode("utf-8")))
    print("ICMP:  ")
    pass

def processUDPHeader(hexPacket):
    '''
    This function takes in the UDP header in hex and processes it
    :param hexPacket: packet header to be processed
    :return:
    '''
    print("UDP:  ----UDP Header----")
    print("UDP:  ")
    print('UDP:  Source Port= ' + str(int(hexPacket[68:72].decode("utf-8"), 16)))
    print('UDP:  Destination Port= ' + str(int(hexPacket[72:76].decode("utf-8"), 16)))
    print('UDP:  Length= ' + str(int(hexPacket[76:80].decode("utf-8"), 16)))
    print('UDP:  Checksum= ' + str(hexPacket[80:84].decode("utf-8")))
    data = hexPacket[84:]
    print("UDP:  ")
    print("UDP:  Data: (first 64 bytes)")
    for i in range(32, 160, 32):
        if len(data) <= 0:
            break
        dataToConvert = data[:32]
        asciiData = convertToAscii(dataToConvert)
        toPrint = formatString(dataToConvert.decode("utf-8"))
        print("UDP:  " + toPrint + "\t" '"' + str(asciiData) + '"')
        data = data[i:]
    print("UDP:  ")


def main():
    '''
    This method takes the packet dump in binary through command line and processes the headers.
    :return:
    '''

    if len(sys.argv) <=1:
        print("Enter the path to the binary packet dump:")
        filename = input()
    else:
        filename = sys.argv[1]  # take input of file through command line
    with open(filename, 'rb') as f:
        content = f.read()

    hexPacket = binascii.hexlify(content)
    print("ETHER:  ----Ether Header----")
    print("ETHER:  ")
    print("ETHER:  Packet Size= " +str(len(hexPacket)//2) +" bytes")
    destinationIP = str(hexPacket[0:2].decode("utf-8")) +":" +str(hexPacket[2:4].decode("utf-8")) +":" +str(hexPacket[4:6].decode("utf-8")) +":" +str(hexPacket[6:8].decode("utf-8")) +":" +str(hexPacket[8:10].decode("utf-8")) +":" +str(hexPacket[10:12].decode("utf-8"))
    sourceIP = str(hexPacket[12:14].decode("utf-8")) +":" +str(hexPacket[14:16].decode("utf-8")) +":" +str(hexPacket[16:18].decode("utf-8")) +":" +str(hexPacket[18:20].decode("utf-8")) +":" +str(hexPacket[20:22].decode("utf-8")) +":" +str(hexPacket[22:24].decode("utf-8"))
    print('ETHER:  Destination: ' +destinationIP )
    print('ETHER:  Source: ' +sourceIP )
    ethertype = hexPacket[24:28]
    if ethertype == b'0800':
        print("ETHER:  Ethertype= " +ethertype.decode("utf-8") + " (IP)")
        print("ETHER:  ")
        processIPHeader(hexPacket)

if __name__ == "__main__":
    main()
