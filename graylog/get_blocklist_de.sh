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

# Download the all.txt file, ignoring HTTPS warnings or errors
curl -k -o "${download_path}${download_filename}" $url

# Create a temporary file to store the modified content
temp_file="${temp_path}${temp_filename}"

# Add the header row
echo "ip,blocklist" > "$temp_file"

# Process the file line by line, adding ,"blocklist.de" to each line
while IFS= read -r line
do
  echo "${line},\"blocklist.de\"" >> "$temp_file"
done < "${download_path}${download_filename}"

# Replace the original file with the modified file
mv "$temp_file" "${download_path}${download_filename}"

echo "Processing complete. The file has been saved as ${download_path}${download_filename}"
