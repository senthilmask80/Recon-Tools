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
