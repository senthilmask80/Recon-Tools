#!/bin/bash

. ./Recon-Tools.cfg

clear

banner
sleep 3

echo
echo "Swastik Web Scanner, Created by Pragnya IT Ingra	"
echo
echo " NO:	Name:	"
echo "----	-----	"
echo
echo " 01	Footprint Domains	"
echo " 02	Subdomain Enumeration	"
echo " 03	Certificate Enumeration	"
echo " 04	Ports Scan		"
echo " 05	Visual Identification	"
echo " 06	WAF Identification	"
echo " 07	Github Recon		"
echo " 08	Wayback Enumeration	"
echo " 09	Javascript Endpoints	"
echo " 10	S3-Bucket-Bruteforcing	"
echo " 11	Content Discovery	"
echo " 12	Web-Application-Attacks	SSRF	"
echo " 13	Web-Application-Attacks	CORS	"
echo " 14	Web-Application-Attacks	CSRF	"
echo " 15	Web-Application-Attacks	XSS	"
echo " 16	Web-Application-Attacks	Command Injection	"
echo " 17	Web-Application-Attacks	Open Redirect		"
echo
echo " 98	Help			"
echo " 99	Report Bug		"
echo " 00	Close and Exit Tools	"
echo
echo -n " ?:- Your Option:-   "
read userinput
echo

#if [[ $EUID -ne 0 ]]; then
#   echo "This script must be run as root" 
#   exit 1
#fi

    if [[ -n "$userinput" ]] ; then

        nodigits="$(echo $userinput | sed 's/[[:digit:]]//g')"

        if [[ ! -z $nodigits ]] ; then

            print "Invalid number format! Only digits, no commas, spaces, etc." 

        fi
    fi

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
mkdir -p $domain/subdomain-takeover
#mkdir -p $domain/ports
mkdir -p $domain/alive-subdomain
#mkdir -p $domain/visual-recon
mkdir -p $domain/content-discovery
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
    "$fold1/subfinder" -silent -d $domain -all -t $THREADS | "$fold1/anew" -q ./$domain/subdomain/subfinder.txt
    "$fold1/findomain" -t $domain -u ./$domain/subdomain/findomain.txt
    python3 "$fold1/sublist3r" -d $domain -t $THREADS -v -o ./$domain/subdomain/sublist3r.txt
    "$fold1/amass" enum -passive -d $domain -o ./$domain/subdomain/amass.txt
    "$fold1/Sudomy-1.2.0/sudomy" -d $domain --all | tee ./$domain/subdomain/sudomy.txt
    "$fold1/waybackurls" $domain | "$fold1/unfurl" -u domains | "$fold1/anew" -q ./$domain/subdomain/waybackurls.txt
    "$fold1/knockpy" $domain -th $threads --no-http-code 404 500 530 -o ./$domain/subdomain/knockpy
    "$fold1/SubDog/subdog" -d $domain >> ./$domain/subdomain/subdog.txt
    python3 "$fold1/subscraper-2.2.1/subscraper.py" -all -r ./$domain/subdomain/subscraper.txt
    "$fold1/anubis" -tip $domain -o ./$domain/subdomain/anubis_result
    "$fold1/SubDomainizer/SubDomainizer.py" -u $domain -o ./$domain/subdomain/subdomainizer.txt
    python3 "$fold1/github-subdomains.py" -t $GITHUB_API_TOKEN -d $domain | anew -q ./$domain/subdomain/github.txt
}

sub_crt(){
    python3 "$fold1/ctfr/ctfr.py" -d $domain | "$fold1/unfurl" domains | "$fold1/anew" -q ./$domain/subdomain/ctfr.txt
}

subactive(){
   # "$fold1/ffuf" -w $FUZZ_WORDLIST -u https://FUZZ.$domain -t $threads -H $HEADER -mc 200 -r -v | grep "| URL |" | awk '{print $4}' | sed 's/^http[s]:\/\///g' | "$fold1/anew" -q ./$domain/subdomain/ffuf.txt
    "$fold1/gobuster" dns -d $domain -z -q -t $threads -w $GOBUSTER_WORDLIST | awk '{$1=""; print $2}' | "$fold1/anew" -q ./$domain/subdomain/gobuster.txt
    # "$fold1/amass" enum  -src -ip -brute -min-for-recursive 2 -d $domain & sleep 30 kill $! -o ./$domain/subdomain/amass_passive.txt
   # chaos -d $domain
}


combinesub(){
    cat ./$domain/subdomain/*.txt | "$fold1/anew" -q ./$domain/subdomain/all_subdomain.txt
}


sub_dns(){
    cat ./$domain/subdomain/all_subdomain.txt | "$fold1/dnsx" -r $RESOLVERS_TRUSTED -a -aaaa -cname -ns -ptr -mx -soa -silent -retry 3 -json -o ./$domain/subdomain/subdomain_dnsregs.json
    cat ./$domain/subdomain/subdomain_dnsregs.json | jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' | grep ".$domain$" | "$fold1/anew" -q ./$domain/subdomain/dnsx_dns_subdomains.txt

    "$fold1/puredns" resolve ./$domain/subdomain/dnsx_dns_subdomains.txt -r $DNSVALIDATOR_RESOLVERS | "$fold1/anew" -q ./$domain/subdomain/dnsx_resolve_subdomains.txt
}

sub_brute(){
    # Dns Bruteforcing
    "$fold1/puredns" bruteforce $ASSETNOTE_DNS_WORDLIST $domain -r $DNSVALIDATOR_RESOLVERS | "$fold1/anew" -q ./$domain/subdomain/puredns_brute_subdomain.txt
    "$fold1/puredns" resolve ./$domain/subdomain/puredns_brute_subdomain.txt -r $DNSVALIDATOR_RESOLVERS | "$fdold1/anew" -q ./$domain/subdomain/puredns_resolve_subdomain.txt

    # Removing Unnecassery files
    # rm -rf ./$domain/subdomain/gotator_subdomains.txt
}

sub_scraping(){
    keydomain=${domain%%.*}
    "$fold1/gospider" -S ./$domain/subdomain/all_alive.txt --js --subs -t $GOSPIDER_THREADS -c 10 -u -d 3 --sitemap --robots -w -r | "$fold1/anew" -q ./$domain/content-discovery/gospider_urls.txt
    cat ./$domain/content-discovery/gospider_urls.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | "$fold1/unfurl" -u domains | grep "$keydomain" | "$fold1/anew" -q ./$domain/subdomain/gospider_subdomains_DNS.txt
    "$fold1/puredns" resolve ./$domain/subdomain/gospider_subdomains_DNS.txt -r $DNSVALIDATOR_RESOLVERS | "$fold1/anew" -q ./$domain/subdomain/gospider_resolve_subdomains.txt

}

sub_permut(){
    # Permutation/Alterations
    "$fold1/gotator" -sub ./$domain/subdomain/all_subdomain.txt -perm $PERMUTATIONS_WORDLIST -depth 1 -numbers 10 -mindup -adv -md -t $GOTATOR_THREADS -silent | "$fold1/anew" -q ./$domain/subdomain/gotator_subdomains.txt
    "$fold1/puredns" resolve ./$domain/subdomain/gotator_subdomains.txt -r $DNSVALIDATOR_RESOLVERS | "$fold1/anew" -q ./$domain/subdomain/gotator_resolve_subdomain.txt
}


subtakeover(){
    "$fold1/subjack" -w ./$domain/subdomain/all_subdomain.txt -t $threads -timeout 30 -o ./$domain/subdomain-takeover/subjack.txt -ssl -c "$fold2"/fingerprints.json
    # dig $domain
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


sub_passive
sub_crt
subactive
combinesub
sub_dns
sub_brute
sub_scraping
sub_permut
subtakeover

echo -e "${GREEN}[+]Finishing The Enumeration OR The Reconnaisses...!!!"
