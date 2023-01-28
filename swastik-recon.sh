#!/bin/bash

. ./Recon-Tools.cfg

#if [[ $EUID -ne 0 ]]; then
#   echo "This script must be run as root" 
#   exit 1
#fi

domain=$1
url=$2

Usage() { #instant
       echo -e "Usage: ||| ./Recon-Tools-New01.sh -d 'DomainName' "
       exit 1
}

#if current directory contains $name as a folder, delete a folder with the same name
if [ -d "$dname" ]; then
        rm -rf $dname
fi

# Recon Directory Path
mkdir -p $domain
#mkdir -p $domain/osint-info
mkdir -p $domain/subdomain
#mkdir -p $domain/ips
#mkdir -p $domain/subdomain-takeover
#mkdir -p $domain/ports
#mkdir -p $domain/alive-subdomain
#mkdir -p $domain/visual-recon
#mkdir -p $domain/content-discovery
#mkdir -p $domain/parameters
#mkdir -p $domain/js-files
#mkdir -p $domain/github
#mkdir -p $domain/wafchecks
#mkdir -p $domain/gf-patterns
#mkdir -p $domain/vulnerabilities
#mkdir -p $domain/nuclei
#mkdir -p $domain/cms-vulnerabilities
#mkdir -p $domain/buckets
#mkdir -p $domain/technologies


echo -e "${GREEN}[+]Start Subdomain Enumeretion...!!!"


###############################################################################################################
############################################### SUBDOMAINS ####################################################
###############################################################################################################

sub_passive(){
    "$fold1/assetfinder" --subs-only $domain | "$fold1/anew" -q ./$domain/subdomain/assetfinder.txt
    "$fold1/subfinder" -silent -d $domain -all -t $subfinder_threads | "$fold1/anew" -q ./$domain/subdomain/subfinder.txt
    "$fold1/findomain" -t $domain --external-subdomains -r -u ./$domain/subdomain/findomain.txt
    python3 "$fold1/sublist3r" -d $domain -t $threads -v -o ./$domain/subdomain/sublist3r.txt
    "$fold1/amass" enum -passive -d $domain -o ./$domain/subdomain/amass.txt
    # sudomy -d $domain --all | tee ./$domain/subdomain/sudomy.txt
    "$fold1/waybackurls" $domain | "$fold1/unfurl" -u domains | "$fold1/anew" -q ./$domain/subdomain/waybackurls.txt
    "$fold1/knockpy" $domain -th $threads --no-http-code 404 500 530 -o ./$domain/subdomain/knock.txt
    "$fold1/SubDog/subdog" -d $domain >> ./$domain/subdomain/subdog.txt
    python3 "$fold1/subscraper-2.2.1/subscraper.py" -all -r ./$domain/subdomain/subscraper.txt
    "$fold1/anubis" -tip $domain -o ./$domain/subdomain/anubis_result_${date +%F}.txt
    # python3 ~/tools/github-subdomains.py -t $GITHUB_API_TOKEN -d $domain | anew -q ./$domain/subdomain/github.txt
}

sub_crt(){
    python3 "$fold1/ctfr/ctfr.py" -d $domain | "$fold1/unfurl" domains | "$fold1/anew" -q ./$domain/subdomain/ctfr.txt
}

subactive(){
   # "$fold1/ffuf" -w $fuzz_wordlists -u https://FUZZ.$domain -t $threads -H $HEADER -mc 200 -r -v | grep "| URL |" | awk '{print $4}' | sed 's/^http[s]:\/\///g' | "$fold1/anew" -q ./$domain/subdomain/ffuf.txt
    "$fold1/gobuster" dns -d $domain -z -q -t $threads -w $gobuster_wordlists | awk '{$1=""; print $2}' | "$fold1/anew" -q ./$domain/subdomain/gobuster.txt
   # "$fold1/amass" enum  -src -ip -brute -min-for-recursive 2 -d $domain -o ./$domain/subdomain/amass_passive.txt
   # chaos -d $domain
}


combinesub(){
    cat ./$domain/subdomain/*.txt | "$fold1/anew" -q ./$domain/subdomain/all_subdomain.txt
}

test(){
     python3 "$fold1/subscraper-2.2.1/subscraper.py" --all $domain -r ./$domain/subdomain/subscraper.txt
}

# HTTProbe
#echo -e "${GREEN}[+]Starting HTTProbe...!!!"
#cat Final-Subsdomains-$domain01.txt | sort -u | uniq -u | "$fold/httprobe" | tee $domain01-alive.txt

# Get-Title
#echo -e "${GREEN}[+]Start Get-titles...!!!"
#cat $domain01-alive.txt | get-titles

# Subdomain Takeover Scan
#echo -e "${GREEN}[+]Start Subdomain Takeover Scan...!!!"
#"$fold/subjack" -w Final-Subsdomains-$domain01.txt -t 20 -ssl -c ~/tools/fingerprints.json -v 3 -o subjack.txt
#"$fold/subzy" -targets Final-Subsdomains-$domain01.txt -hide_fails --verify_ssl -concurrency 20 | sort -u | tee "subzy.txt"


# Use Waybackurls to find URLs in the Wayback Machine
#echo "Running Waybackurls to find URLs in the Wayback Machine...!!!";
#"$fold/waybackurls" $domain01 > waybackurls_results.txt

# Use Aquatone to take screenshots of the discovered URLs
#echo "Running Aquatone to take screenshots of the discovered URLs...!!!!";
#cat waybackurls_results.txt amass_results.txt amass_results.txt subfinder_results.txt | sort -u | "$fold/aquatone" -screenshot-timeout 19 -out aquatone_screenshots/

#sub_passive
#sub_crt
#subactive
combinesub
#test

echo -e "${GREEN}[+]Finishing The Enumeration OR The Reconnaisses...!!!"
