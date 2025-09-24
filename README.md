# Portscanning
Network scanning is a process used to discover devices, services, and vulnerabilities in a network. It is widely used by network administrators for troubleshooting and by cybersecurity professionals for ethical hacking and security assessments.
requirements
pip install nmap
pip install scapy
pip install socket
                      
import socket
import nmap
import scapy
def function_menu():
    """Display the menu options for the network."""
    print("/n")
    print("---------------")
    print("1. Port scan using socket")
    print("2. Port scan using scapy")
    print("3. Port scan using nmap")
    print("0. Exit")
    print("---------------")

def check_host(ip, port=80):
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #socket.AF_INET = Used Standart IPV4 Protocol
        #socket.SOCK_STREAM = Used TCP stream
        
        socket.settimeout(1)
        #socket.settimeout() = Set timeout for socket's operation

        result = socket.connect_ex((ip, port==8080))
        #connect_ex = attempts to connect to the specified ip and port

        if result == 0:
            print(f"Host (ip) is UP on port (port)")
        else : 
            print(f"Host (ip) is DOWN on port (port)")

        socket.close()

    except Exception as e:
        print(f"Error : (e)")


from scapy.all import IP , ICMP, sr
def ping_sweep(network): #network = IP range
    active,_ = sr(IP(dst=network)/ICMP(), timeout=2, verbose=False)
#sr = send and receive
    for sent, received in active:
        print(f"Host {received.src} is UP")

def portscannmap(ip_add,port_no):
    nm = nmap.PortScanner()
    nm.scan(ip_add,port_no)
    for host in nm.all_hosts():
        print(f"Host:{host}({nm[host].hostname()})")
        print(f"state:{nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"")
            print(f"Protocal:{proto}")
            lport = nm[host][proto].keys()

            for port in lport:
                state=nm[host][proto][port]['state']
                print(f"port:{port} \t state: {state}")


def main():
    """Main function to run the interface."""
    while True:
        function_menu()
        choice = input("Enter your choice (0-3): ")
        
        if choice == '1':
            print("Port scan using socket")
            check_host((input("enter your ip :")), (str(input("enter your ports :")))) 
            
        elif choice == '2':
            print("Port scan using scapy")
            ping_sweep ((input("enter your ip :")), (str(input("enter your ports :"))))
            
        elif choice == '3':
            print("Port scan using nmap")
            portscannmap ((input("enter your ip :")), (str(input("enter your ports :"))))

        elif choice == '0':
            print("Exiting...")
            break

        else:
            print("Invalid input. Please enter a number from 0 to 3.")

if __name__ == "__main__":
    main()
