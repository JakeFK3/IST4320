from scapy.all import *

def sniff_email(packet):
    if packet.haslayer(TCP) and packet[TCP].dport in ports:
        # Extract the raw data from the packet
        raw_data = packet[TCP].payload
        
        # Convert the raw data to a string
        data_str = str(raw_data)
        
        # Check if the data contains an email message
        if "From:" in data_str and "To:" in data_str and "Subject:" in data_str:
            print("Email packet detected:")
            print(data_str)
            # Save the email message to a file
            with open("email_log.txt", "a") as file:
                file.write(data_str + "\n")

# Prompt the user for the range of ports
start_port = int(input("Enter the starting port number: "))
end_port = int(input("Enter the ending port number: "))
ports = range(start_port, end_port + 1)

# Sniff packets on the network interface
sniff(prn=sniff_email, filter=f"tcp port {start_port}-{end_port}")

# Prompt the user to stop the scanning
input("Press Enter to stop scanning and save the findings to 'email_log.txt'.")
