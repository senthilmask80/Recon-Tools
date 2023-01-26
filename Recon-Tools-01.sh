#!/bin/bash

# Set target URL
target_url="https://www.example.com"

# Perform subdomain enumeration
echo "Performing subdomain enumeration ..."
subdomains=$(dig -t axfr $target_url | grep $target_url | awk '{print $1}')
echo "Found the following subdomains: $subdomains"

# Perform content discovery on subdomains
echo "Performing content discoveryon subdomains..."
for subdomain in $subdomains; do
  echo "Scanning $subdomain..."
  wfuzz -c -z file,/usr/share/seclists/Discovery/Web_Content/common.txt
$subdomain/FUZZ
done

# Perform directory discovery on target URL
echo "Performing directory discovery on target URL ..."
wfuzz -c -z file,/usr/share/seclists/Discovery/Web_Content/common.txt
$target_url/FUZZ

echo "Advance Recon Process Complete..."
