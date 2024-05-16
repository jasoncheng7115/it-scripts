#!/bin/bash

# Define the download URL
url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/iblocklist_ciarmy_malicious.netset"

# Define the download path and filename using variables
download_path="/etc/graylog/server/" # You can change this to your desired download path
download_filename="blocklist_ciarmy_malicious.csv" # You can change this to your desired filename

# Define the temporary file path and filename using variables
temp_path="/tmp/" # You can change this to your desired temporary file path
temp_filename="tmp_ciarmy_malicious.csv" # You can change this to your desired temporary filename

# Download the netset file, ignoring HTTPS warnings or errors
curl -k -o "${temp_path}${temp_filename}" $url

# Create the final file path
final_file="${download_path}${download_filename}"

# Add the header row to the final file
echo "ip,blocklist" > "$final_file"

# Process the temporary file line by line
# Remove lines starting with # and add ,"ciarmy_malicious" to each IP
# Save intermediate results to a new temporary file
intermediate_temp_file="${temp_path}intermediate_${temp_filename}"
while IFS= read -r line
do
  if [[ ! "$line" =~ ^# ]]; then
    echo "${line},\"ciarmy_malicious\"" >> "$intermediate_temp_file"
  fi
done < "${temp_path}${temp_filename}"

# Remove duplicate lines and append to final file
sort "$intermediate_temp_file" | uniq >> "$final_file"

# Optionally, you can remove the temporary files if they're no longer needed
rm "${temp_path}${temp_filename}" "$intermediate_temp_file"

echo "Processing complete. The file has been saved as ${final_file}"


