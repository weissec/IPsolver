#!/usr/bin/python3
# w315
# Usage: python ipsolver.py ips.txt output.csv

import argparse
import ipwhois
import csv

def get_ip_info(ip_addresses, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Organization', 'ASN', 'NetName', 'CIDR']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for ip in ip_addresses:
            try:
                result = ipwhois.IPWhois(ip).lookup_rdap()
                org_name = result.get('asn_description', 'N/A')
                asn = result.get('asn', 'N/A')
                netname = result.get('network', {}).get('name', 'N/A')
                cidr = result.get('asn_cidr', 'N/A')
                writer.writerow({
                    'IP': ip,
                    'Organization': org_name,
                    'ASN': asn,
                    'NetName': netname,
                    'CIDR': cidr
                })
                print("- IP: " + ip + " | Owner: " + org_name)
                
            except Exception as e:
                print(f"Error processing IP {ip}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT tool that retrieves Whois information for a list of IP addresses.")
    parser.add_argument("file", help="File containing a list of IP addresses")
    parser.add_argument("output", help="Output CSV file")
    args = parser.parse_args()
    print('---------------------------------------------------')
    print('IPsolver.py - Quick bulk IP Addresses Whois search.')
    print('---------------------------------------------------\n')
    with open(args.file, 'r') as f:
        ips = [line.strip() for line in f.readlines()]
        print('[+] Found ' + str(len(ips)) + ' IP Addresses. Processing:')
    get_ip_info(ips, args.output)
    print('[+] Finished processing. Results saved in: ' + args.output)
