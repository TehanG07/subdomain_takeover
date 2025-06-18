#!/bin/bash

# Colors
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
NC="\033[0m"

# Banner
clear
echo -e "${BLUE}"
echo "███████╗██╗   ██╗██████╗ ███████╗███╗   ██╗ ██████╗ ███╗   ██╗"
echo "██╔════╝██║   ██║██╔══██╗██╔════╝████╗  ██║██╔═══██╗████╗  ██║"
echo "███████╗██║   ██║██████╔╝█████╗  ██╔██╗ ██║██║   ██║██╔██╗ ██║"
echo "╚════██║██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╗██║"
echo "███████║╚██████╔╝██║     ███████╗██║ ╚████║╚██████╔╝██║ ╚████║"
echo "╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝"
echo -e "${YELLOW}              Subdomain Takeover Detection by TehanG07${NC}\n"

# Get domain and fingerprint path
read -p "Enter the target domain: " domain
read -p "Enter path to fingerprints JSON file: " json_file

# Step 1: Subdomain enumeration
echo -e "${BLUE}[*] Enumerating subdomains using Subfinder...${NC}"
subfinder -d "$domain" -all -silent -o all_subdomains.txt

# Step 2: DNS resolution and CNAME check
echo -e "${BLUE}[*] Resolving subdomains and checking CNAMEs using DNSX...${NC}"
dnsx -l all_subdomains.txt -a -cname -json -o cname_output.json

# Step 3: Loop through DNSX results
echo -e "${BLUE}[*] Checking for potential takeovers...${NC}"
> confirmed_takeovers.txt

while read -r line; do
    subdomain=$(echo "$line" | jq -r '.host')
    cname=$(echo "$line" | jq -r '.cname')

    # Skip if no CNAME
    if [[ "$cname" == "null" || -z "$cname" ]]; then
        continue
    fi

    # Curl response
    response=$(curl -sL --max-time 10 "$subdomain")

    # Loop through services in JSON
    for service in $(jq -r '.[].service' "$json_file"); do
        fingerprints=$(jq -r --arg svc "$service" '.[] | select(.service==$svc) | .fingerprint[]' "$json_file")
        status=$(jq -r --arg svc "$service" '.[] | select(.service==$svc) | .status' "$json_file")

        for fp in $fingerprints; do
            if echo "$response" | grep -qF "$fp"; then
                echo -e "${RED}[+] $subdomain => $service ($status) | Fingerprint: $fp${NC}"
                echo "$subdomain => $service => fingerprint: $fp" >> confirmed_takeovers.txt
                break 2
            fi
        done
    done

done < cname_output.json

echo -e "\n${GREEN}[✓] Done. Results saved in confirmed_takeovers.txt${NC}"
                                                                                                                                                 
