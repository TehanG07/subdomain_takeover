#!/bin/bash

INPUT="sub.txt"
HTTP_404="http_404_subs.txt"
SUBZY_OUTPUT="subzy_raw.txt"
VULNERABLE_SUBS="confirmed_takeovers.txt"
FINGERPRINTS_JSON="fingerprints.json"  # downloaded from shifa123 repo

# Check required tools
for tool in subzy curl jq; do
  if ! command -v $tool &> /dev/null; then
    echo "$tool not installed. Please install it first."
    exit 1
  fi
done

echo "[*] Step 1: Checking 404 status subdomains..."
> "$HTTP_404"
while read -r sub; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -I "https://$sub")
  if [[ "$status" == "404" ]]; then
    echo "$sub" >> "$HTTP_404"
  fi
done < "$INPUT"

echo "[*] Step 2: Running Subzy on 404 subdomains..."
subzy run --targets "$HTTP_404" --hide_fails > "$SUBZY_OUTPUT"

echo "[*] Step 3: Checking for unclaimed fingerprints..."
> "$VULNERABLE_SUBS"
while read -r line; do
  # Match only VULNERABLE lines
  if [[ "$line" == *"[ VULNERABLE ]"* ]]; then
    sub=$(echo "$line" | awk '{print $5}')
    provider=$(echo "$line" | grep -oP '\[ \K[^]]+(?= \])$')
    
    # Now get full curl content to match fingerprint
    html=$(curl -sL "https://$sub")
    
    # Search fingerprint match from shifa123 repo
    matched=$(jq -r ".fingerprints[] | select(.service==\"$provider\") | .indicators[] | select(.!=null) | select(. | test(\"$html\"; \"i\"))" "$FINGERPRINTS_JSON")
    
    if [[ ! -z "$matched" ]]; then
      echo "[✔] $sub is vulnerable ($provider)" | tee -a "$VULNERABLE_SUBS"
    fi
  fi
done < "$SUBZY_OUTPUT"

echo "✅ Done! Confirmed takeovers are saved in $VULNERABLE_SUBS"
