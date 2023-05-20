import argparse
import logging.config
from dns_traffic_analyzer import DNSTrafficAnalyzer

logging.config.fileConfig("logging_config.ini")
logger = logging.getLogger("DNSAnalyzer")

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

    pcap_file = args.pcap_file
    analyzer = DNSTrafficAnalyzer(pcap_file)
    analyzer.analyze_dns_traffic()
