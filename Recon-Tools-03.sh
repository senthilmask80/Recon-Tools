#!/bin/bash

# Check if the required tools are installed
command -v amass > /dev/null 2>&1 || {
  echo >&2 "Amass is not installed. Aborting...!!!"; exit 1; }
command -v aquatone > /dev/null 2&1 || {
  echo >&2 "Aquatone is not installed. Aborting...!!!"; exit 1; }
command -v subfinder > /dev/null 2&1 || {
  echo >&2 "Subfinder is not installed. Aborting...!!!"; exit 1; }
command -v waybackurls > /dev/null 2&1 || {
  echo >&2 "Waybackurls is not installed. Aborting...!!!"; exit 1; }

# Set the target domain
echo -n "Enter the target domain: "
read domain01

# Use amass to find subdomains
echo "Running Amass to find subdomains...!!!";
amass enum -d $domain01 -o amass_results.txt

# Use subfinder to find additional subdomains
echo "Running Subfinder to find additional subdomains...!!!";
subfinder -d $domain01 -o subfinder_results.txt

# Use Waybackurls to find URLs in the Wayback Machine
echo "Running Waybackurls to find URLs in the Wayback Machine...!!!";
waybackurls $domain01 > waybackurls_results.txt

# Use Aquatone to take screenshots of the discovered URLs
echo "Running Aquatone to take screenshots of the discovered URLs...!!!!";
cat waybackurls_results.txt amass_results.txt amass_results.txt subfinder_results.txt | sort -u | aquatone -out aquatone_results
