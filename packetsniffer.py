from scapy.all import sniff

currentips = []
currentips2 = []
def snifferip(packet):
 try:
    src = packet[0][1].src
    dst = packet[0][1].dst
    if src in currentips:
        return
    elif dst in currentips2:
        return
    else:
        try:
            print(f"source = {src}\ndestination = {dst}\ndestination port = {packet[0][1].dport}\nsource port = {packet[0][1].sport}\npacket = {packet.load}\n")
            return
        except Exception:
            try:
                print(f"source = {src}\ndestination = {dst}\ndestination port = {packet[0][1].dport}\nsource port = {packet[0][1].sport}\n")
                return
            except Exception:
                print(f"source = {src}\ndestination = {dst}\ndesti  nation port = none\nsource port = none\n")
                return
 except Exception as e:
     print(f"error: {e}")

def main1():
    user = input("destination port? (type none if you would like to capture all ports!):   ")
    type = input("protocol? [tcp, udp, ip]:   ")
    if user == "none" or user == "":
        sniff(filter="ip", prn=snifferip)
    elif int(user) in range(1, 65535, 1):
        sniff(filter=f"{type} and port {int(user)}", prn=snifferip)
    else:
        print("invalid port was passed.")
        main1()

main1()


