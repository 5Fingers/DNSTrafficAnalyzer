import logging
import dpkt
from dpkt import dns
import socket
import requests as requests
import time
import logging.config

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
                                        logger.warning(f'Suspicious domain lookup: {domain} from {ip.src} to {ip.dst}')

                                # Check for potential DNS tunneling
                                if self.is_dns_tunneling(dns):
                                    logger.warning(f'Potential DNS tunneling detected from {ip.src} to {ip.dst}')

                                # Check for communication with known malicious domains
                                if self.is_malicious_communication(dns):
                                    logger.warning(f'Communication with malicious domain detected from {ip.src} to {ip.dst}')
                                    
                                # Check for DNSSEC validation failures
                                if self.is_dnssec_validation_failure(dns):
                                    logger.warning('DNSSEC validation failure detected')

                                # Check for DNS amplification attacks
                                if self.is_dns_amplification_attack(dns):
                                    logger.warning('DNS amplification attack detected')

                                # Check for fast flux domains
                                if self.is_fast_flux_domain(dns):
                                    logger.warning('Fast flux domain detected')

                                # Check for DNS rebinding
                                if self.is_dns_rebinding(dns):
                                    logger.warning('DNS rebinding detected')

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
        # Fetch the latest 100 malicious IPs from VirusTotal
        malicious_ips = self.fetch_malicious_ips()

        for rr in dns.an:
            if isinstance(rr, dpkt.dns.DNSRR):
                ip_address = socket.inet_ntoa(rr.rdata)
                if ip_address in malicious_ips:
                    return True
        return False

    def is_dnssec_validation_failure(self, dns):
        # Check if the DNS response has DNSSEC validation failure flag set
        if dns.rcode & dpkt.dns.DNS_RCODE_BADSIG:
            return True
        return False

    def is_dns_amplification_attack(self, dns):
        # Check if the DNS response is larger than the query
        query_size = sum(len(qname) + 1 + 2 + 2 for qname in dns.qd[0].name.split(b'.'))
        response_size = sum(len(rr.rname) + 2 + 2 + 4 + 2 + 2 + len(rr.rdata) for rr in dns.an)
        if response_size > query_size:
            return True
        return False

    def is_fast_flux_domain(self, dns):
        # Check if the DNS response contains multiple IP addresses for the same domain
        ip_addresses = set()
        for rr in dns.an:
            if isinstance(rr, dpkt.dns.DNSRR):
                if rr.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA):
                    ip_address = socket.inet_ntoa(rr.rdata)
                    if ip_address in ip_addresses:
                        return True
                    ip_addresses.add(ip_address)
        return False

    def is_dns_rebinding(self, dns):
        # Check if the DNS response contains an IP address that does not match the query domain
        query_domain = dns.qd[0].name.lower().decode('utf-8')
        for rr in dns.an:
            if isinstance(rr, dpkt.dns.DNSRR):
                if rr.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA):
                    ip_address = socket.inet_ntoa(rr.rdata)
                    if not self.ip_matches_domain(ip_address, query_domain):
                        return True
        return False

    def ip_matches_domain(self, ip_address, domain):
        try:
            reverse_ip = dns.reversename.from_address(ip_address)
            rdns = str(dns.resolver.query(reverse_ip, "PTR")[0]).lower()
            return domain in rdns
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except dns.resolver.Timeout:
            logger.warning("DNS resolution timeout occurred")
            return False

    def fetch_malicious_ips(self):
        api_key = "VIRUSTOTAL_API_KEY"
        six_months_ago = int(time.time()) - (180 * 24 * 60 * 60)  # 180 days in seconds

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses?filter=last_analysis_date%3A>{six_months_ago}&limit=100"
            headers = {"x-apikey": api_key}

            response = requests.get(url, headers=headers)
            response.raise_for_status()
            json_data = response.json()

            # Extract the malicious IP addresses
            malicious_ips = [ip['attributes']['ip_address'] for ip in json_data['data']]
            return malicious_ips

        except requests.exceptions.RequestException as e:
            logger.error(f"Error occurred while fetching malicious IPs from VirusTotal: {str(e)}")
            return []
