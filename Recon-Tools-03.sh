#!/bin/bash

# PATH="$PATH:$HOME/Recon-Bin:$HOME/Recon-Tools"
fold1=$HOME/Recon-Bin/
fold2=$HOME/Recon-Tools/

# Colors
BOLD="\e[1m"
NORMAL="\e[0m"
GREEN="\e[92m"


# Set the target domain
echo -e "${GREEN}[+]Enter the target domain: "
read domain01

echo -e "${GREEN}[+]Start Subdomain Enumeretion...!!!"

# Use Assetfinder
echo -e "${GREEN}[+]Running Assetfinder to find subdomains...!!!"
"$fold1/assetfinder" --subs-only $domain01 | sort -u | tee assetfinder_results.txt

# Use amass to find subdomains
echo -e "${GREEN}[+]Running Amass to find subdomains...!!!"
"$fold1/amass" enum -d $domain01 -o amass_results.txt

# Use subfinder to find subdomains
echo -e "${GREEN}[+]Running Subfinder to find subdomains...!!!"
"$fold1/subfinder" -d $domain01 -o subfinder_results.txt

# Use sublist3r to find subdomains
echo -e "${GREEN}[+]Running Sublist3r to find subdomains...!!!"
sublist3r -d $domain01 -o sublist3r_results.txt

# Filtering
echo -e "${GREEN}[+]Starting Filtering...!!!"
cat assetfinder_results.txt amass_results.txt subfinder_results.txt sublist3r_results.txt | sort -u | grep -v "*" | sort -u | tee Final-Subsdomains-$domain01.txt 

# HTTProbe
echo -e "${GREEN}[+]Starting HTTProbe...!!!"
cat Final-Subsdomains-$domain01.txt | sort -u | uniq -u | "$fold1/httprobe" | tee $domain01-alive.txt

# Get-Title
echo -e "${GREEN}[+]Start Get-titles...!!!"
cat $domain01-alive.txt | get-titles

# Subdomain Takeover Scan
echo -e "${GREEN}[+]Start Subdomain Takeover Scan...!!!"
"$fold1/subjack" -w Final-Subsdomains-$domain01.txt -t 20 -ssl -c ~/tools/fingerprints.json -v 3 -o subjack.txt
"$fold1/subzy" -targets Final-Subsdomains-$domain01.txt -hide_fails --verify_ssl -concurrency 20 | sort -u | tee "subzy.txt"


# Use Waybackurls to find URLs in the Wayback Machine
echo "Running Waybackurls to find URLs in the Wayback Machine...!!!";
"$fold1/waybackurls" $domain01 > waybackurls_results.txt

# Use Aquatone to take screenshots of the discovered URLs
echo "Running Aquatone to take screenshots of the discovered URLs...!!!!";
cat waybackurls_results.txt amass_results.txt amass_results.txt subfinder_results.txt | sort -u | "$fold1/aquatone" -screenshot-timeout 19 -out aquatone_screenshots/

echo -e "${GREEN}[+]Finishing The Enumeration OR The Reconnaisses...!!!"
