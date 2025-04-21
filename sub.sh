  GNU nano 8.4                                                                                                                                                                              sub.sh                                                                                                                                                                                        
#!/bin/bash

# Define input file
INPUT_FILE="sub.txt"
OUTPUT_FILE="subzy_results.txt"
DIG_RESULTS_FILE="dig_results.txt"
FINAL_RESULTS="final_results.txt"

# Check if Subzy is installed
if ! command -v subzy &> /dev/null; then
    echo "Subzy is not installed. Please install it first."
    exit 1
fi

# Check if dig is installed
if ! command -v dig &> /dev/null; then
    echo "dig is not installed. Please install it first."
    exit 1
fi

# Run Subzy and save results
echo "Running Subzy on targets..."
subzy run --targets "$INPUT_FILE" --hide_fails > "$OUTPUT_FILE"

# Extract vulnerable subdomains from Subzy output
awk '/\[ VULNERABLE \]/{print $5}' "$OUTPUT_FILE" > subzy_vulnerable.txt

# Run dig for each subdomain
echo "Running dig for each subdomain..."
> "$DIG_RESULTS_FILE"
while read -r subdomain; do
    echo "Checking $subdomain with dig..."
    dig "$subdomain" +short >> "$DIG_RESULTS_FILE"
    echo "$subdomain : $(dig "$subdomain" +short)" >> "$DIG_RESULTS_FILE"
done < "$INPUT_FILE"

# Compare Subzy and dig results
echo "Comparing Subzy and dig results..."
> "$FINAL_RESULTS"
while read -r subdomain; do
    if grep -q "$subdomain" subzy_vulnerable.txt && grep -q "$subdomain" "$DIG_RESULTS_FILE"; then
        echo -e "\033[31m[VULNERABLE] $subdomain (highlighted in red)\033[0m" >> "$FINAL_RESULTS"
    else
        echo "[NOT VULNERABLE] $subdomain" >> "$FINAL_RESULTS"
    fi
done < "$INPUT_FILE"

# Display final results
echo "Final results are saved in $FINAL_RESULTS"
cat "$FINAL_RESULTS"
