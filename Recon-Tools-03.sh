#!/bin/bash

export PATH:PATH:/home/pragnya/Recon-Bin:/home/pragnya/Recon-Tools

# Colors
BOLD="\e[1m"
NORMAL="\e[0m"
GREEN="\e[92m"

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
echo -e "${GREEN}[+]Enter the target domain: "
read domain01

echo -e "${GREEN}[+]Start Subdomain Enumeretion...!!!"

# Use Assetfinder
echo -e "${GREEN}[+]Running Assetfinder to find subdomains...!!!"
assetfinder --subs-only $domain01 | sort -u | tee assetfinder_results.txt

# Use amass to find subdomains
echo -e "${GREEN}[+]Running Amass to find subdomains...!!!"
amass enum -d $domain01 -o amass_results.txt

# Use subfinder to find subdomains
echo -e "${GREEN}[+]Running Subfinder to find subdomains...!!!"
subfinder -d $domain01 -o subfinder_results.txt

# Use sublist3r to find subdomains
echo -e "${GREEN}[+]Running Sublist3r to find subdomains...!!!"
sublist3r -d $domain01 -o sublist3r_results.txt

# Filtering
echo -e "${GREEN}[+]Starting Filtering...!!!"
cat assetfinder_results.txt amass_results.txt subfinder_results.txt sublist3r_results.txt | sort -u | grep -v "*" | sort -u | tee Final-Subsdomains-$domain01.txt 

# HTTProbe
echo -e "${GREEN}[+]Starting HTTProbe...!!!"
cat Final-Subsdomains-$domain01.txt | sort -u | uniq -u | httprobe | tee $domain01-alive.txt

# Get-Title
echo -e "${GREEN}[+]Start Get-titles...!!!"
cat $domain01-alive.txt | get-titles

# Subdomain Takeover Scan
echo -e "${GREEN}[+]Start Subdomain Takeover Scan...!!!"
subjack -w Final-Subsdomains-$domain01.txt -t 20 -ssl -c ~/tools/fingerprints.json -v 3 -o subjack.txt
subzy -targets Final-Subsdomains-$domain01.txt -hide_fails --verify_ssl -concurrency 20 | sort -u | tee "subzy.txt"


# Use Waybackurls to find URLs in the Wayback Machine
echo "Running Waybackurls to find URLs in the Wayback Machine...!!!";
waybackurls $domain01 > waybackurls_results.txt

# Use Aquatone to take screenshots of the discovered URLs
echo "Running Aquatone to take screenshots of the discovered URLs...!!!!";
cat waybackurls_results.txt amass_results.txt amass_results.txt subfinder_results.txt | sort -u | aquatone -screenshot-timeout 19 -out aquatone_screenshots/

echo -e "${GREEN}[+]Finishing The Enumeration OR The Reconnaisses...!!!"
