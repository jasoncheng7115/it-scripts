#!/bin/bash
# jason@jason.tools
# www.jason.tools
# v1.0

# Define the download URL
url="https://lists.blocklist.de/lists/all.txt"

# Define the download path and filename using variables
download_path="/etc/graylog/server/" # You can change this to your desired download path
download_filename="blocklist_de.csv" # You can change this to your desired filename

# Define the temporary file path and filename using variables
temp_path="/tmp/" # You can change this to your desired temporary file path
temp_filename="tmp_blocklist_de.csv" # You can change this to your desired temporary filename

# Download the netset file, ignoring HTTPS warnings or errors
curl -k -o "${temp_path}${temp_filename}" $url

# Create the final file path
final_file="${download_path}${download_filename}"

# Add the header row to the final file
echo "ip,blocklist" > "$final_file"

# Process the temporary file line by line
# Remove lines starting with # and add ,"blocklist.de" to each IP
# Save intermediate results to a new temporary file
intermediate_temp_file="${temp_path}intermediate_${temp_filename}"
while IFS= read -r line
do
  if [[ ! "$line" =~ ^# ]]; then
    echo "${line},\"blocklist.de\"" >> "$intermediate_temp_file"
  fi
done < "${temp_path}${temp_filename}"

# Remove duplicate lines and append to final file
sort "$intermediate_temp_file" | uniq >> "$final_file"

# Optionally, you can remove the temporary files if they're no longer needed
rm "${temp_path}${temp_filename}" "$intermediate_temp_file"

echo "Processing complete. The file has been saved as ${final_file}"


