import argparse
import logging.config
import logging
import dpkt
import socket
import sys

logging.config.fileConfig("logging_config.ini")
logger = logging.getLogger("DNSAnalyzer")


class DNSTrafficAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def analyze_dns_traffic(self):
        try:
            with open(self.pcap_file, 'rb') as pcap:
                pcap_data = dpkt.pcap.Reader(pcap)

                for timestamp, buf in pcap_data:
                    eth = dpkt.ethernet.Ethernet(buf)

                    # Check if the packet is an IP packet
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data

                        # Check if the IP packet is a UDP packet
                        if isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data

                            # Check if the UDP packet is a DNS packet (port 53)
                            if udp.sport == 53 or udp.dport == 53:
                                dns = dpkt.dns.DNS(udp.data)

                                # Check for suspicious domain lookups
                                for query in dns.qd:
                                    domain = query.name.lower().decode('utf-8')
                                    if self.is_suspicious_domain(domain):
                                        logger.warning(f'Suspicious domain lookup: {domain}')

                                # Check for potential DNS tunneling
                                if self.is_dns_tunneling(dns):
                                    logger.warning('Potential DNS tunneling detected')

                                # Check for communication with known malicious domains
                                if self.is_malicious_communication(dns):
                                    logger.warning('Communication with malicious domain detected')

        except FileNotFoundError:
            logger.error(f"PCAP file '{self.pcap_file}' not found")

    def is_suspicious_domain(self, domain):
        # Check if the domain contains a suspicious keyword
        suspicious_keywords = ['malware', 'phishing', 'botnet']
        for keyword in suspicious_keywords:
            if keyword in domain:
                return True
        return False

    def is_dns_tunneling(self, dns):
        # Check if the DNS query type is not A or AAAA
        for query in dns.qd:
            if query.type != dpkt.dns.DNS_A and query.type != dpkt.dns.DNS_AAAA:
                return True
        return False

    def is_malicious_communication(self, dns):
        # Check if the DNS response contains a known malicious IP address
        malicious_ips = ['1.2.3.4', '5.6.7.8']
        for rr in dns.an:
            if isinstance(rr, dpkt.dns.DNSRR):
                if socket.inet_ntoa(rr.rdata) in malicious_ips:
                    return True
        return False


# Example usage:
if __name__ == '__main__':
    print("""                                         
          _____  _   _  _____                          _                    
         |  __ \| \ | |/ ____|       /\               | |                   
         | |  | |  \| | (___ ______ /  \   _ __   __ _| |_   _ _______ _ __ 
         | |  | | . ` |\___ \______/ /\ \ | '_ \ / _` | | | | |_  / _ \ '__|
         | |__| | |\  |____) |    / ____ \| | | | (_| | | |_| |/ /  __/ |   
         |_____/|_| \_|_____/    /_/    \_\_| |_|\__,_|_|\__, /___\___|_|   
                                                          __/ |             
                                                         |___/              
                           By: 5Fingers

    """)
    parser = argparse.ArgumentParser(description='DNS Traffic Analyzer - A tool that captures and analyzes '
                                                 'DNS traffic to identify suspicious domain lookups, potential '
                                                 'DNS tunneling, or communication with malicious domains.')
    parser.add_argument('-p', '--pcap_file', help='Input PCAP file which contains the network data/traffic',
                        required=True, type=str)
    args = parser.parse_args()

    pcap_file = args['pcap_file']
    analyzer = DNSTrafficAnalyzer(pcap_file)
    analyzer.analyze_dns_traffic()
