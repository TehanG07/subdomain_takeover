#!/bin/bash

INPUT="sub.txt"
HTTP_404="http_404_subs.txt"
SUBZY_OUTPUT="subzy_raw.txt"
VULNERABLE_SUBS="confirmed_takeovers.txt"
FINGERPRINTS_JSON="fingerprints.json"  # Must be downloaded and present

# Required tools check
for tool in subzy curl jq; do
  if ! command -v "$tool" &> /dev/null; then
    echo "$tool not installed. Please install it first."
    exit 1
  fi
done

# Step 1: Check 404 subdomains
echo "[*] Step 1: Filtering 404 subdomains from $INPUT..."
> "$HTTP_404"
while read -r sub; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -I "https://$sub")
  if [[ "$status" == "404" ]]; then
    echo "$sub" >> "$HTTP_404"
    echo "[404] $sub"
  else
    echo "[SKIP] $sub returned $status"
  fi
done < "$INPUT"

# Step 2: Run Subzy
echo "[*] Step 2: Running Subzy against 404 subdomains..."
subzy run --targets "$HTTP_404" --hide_fails > "$SUBZY_OUTPUT"

# Step 3: Validate with Fingerprints
echo "[*] Step 3: Validating Subzy results using fingerprints..."
> "$VULNERABLE_SUBS"

while read -r line; do
  if [[ "$line" == *"[ VULNERABLE ]"* ]]; then
    domain=$(echo "$line" | awk '{print $5}')
    provider=$(echo "$line" | grep -oP '\[ \K[^]]+(?= \])$')
    echo "[>] Checking $domain for provider: $provider"

    # Fetch HTML of the domain
    html=$(curl -sL --max-time 10 "https://$domain")

    # Match against fingerprints
    if [[ -f "$FINGERPRINTS_JSON" ]]; then
      matched=$(jq -r --arg html "$html" --arg provider "$provider" '
        .fingerprints[]
        | select(.service == $provider)
        | .indicators[]
        | select(. != null)
        | select($html | test(. ; "i"))
      ' "$FINGERPRINTS_JSON")

      if [[ ! -z "$matched" ]]; then
        echo "[✔] $domain is confirmed vulnerable ($provider)" | tee -a "$VULNERABLE_SUBS"
      else
        echo "[x] $domain had no matching fingerprint"
      fi
    else
      echo "[ERROR] fingerprints.json not found!"
      exit 1
    fi
  fi
done < "$SUBZY_OUTPUT"

echo "✅ Done! Results saved to: $VULNERABLE_SUBS"
