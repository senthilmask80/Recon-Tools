#!/bin/bash

# Subfinder
subfinder -d $1 -o subfinder_output.txt

# Dirsearch
dirsearch -u $1 -e  * -t 50 -w /path/to/wordlist.txt -x 400,403,429,502,503,504 -f -b

# MassDNS
massdns -r /path/to/resolvers.txt -t A -o S -w massdns_output.txt $1

# Sublist3r
sublist3r -d $1 -o sublist3r_output.txt 

# ffuf
ffuf -c -w /path/to/wordlist.txt -u $1/FUZZ -o ffuf_output.txt

# WayBackurls
waybackurls $1 > waybackurls_output.txt

# Nmap
nmap -sV -p- -oN nmap_output.txt $1

# Vulners
vulners -sV -p- -oN vulners_output.txt $1

$ CF-Check
echo "$1" | cf-check

"""
The goal is that you don't need to do a port scan if it's proven that the IP is owned by Cloudflare.
"""

subfinder -silent -d $1 | filter-resolved | cf-check | sort -u | naabu -silent | httprobe

# Javascript recon when target is using Graphql
# find all embedded graphql queries/mutations using bash one liner

cat jsfile.js | nestle -regex '(query|mutation)\s+[a-zA-Z]+[0-9]*[a-zA-Z]+(\([^(\(|\))]+\))*\s*[{:nested:}]' | sed 's/\\n/\n/g'

