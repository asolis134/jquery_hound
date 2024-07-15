import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import date
import re
import hashlib
import json

todays_date = date.today()

class JQueryProbe:
    def __init__(self, probed_url, detected_version, script_hash, date_probed, script_url, is_vulnerable):
        self.probed_url = probed_url
        self.detected_version = detected_version
        self.script_url = script_url
        self.script_hash = script_hash
        self.date_probed = date_probed
        self.is_vulnerable = is_vulnerable

    def to_dict(self):
        return {
            'probed_url': self.probed_url,
            'detected_version': self.detected_version,
            'script_hash': self.script_hash,
            'date_probed': self.date_probed,
            'script_url' : self.script_url,
            'is_vulnerable' : self.is_vulnerable
        }
    

def write_data(probe_list):
    probe_list_dictionary = [vars(probe) for probe in probe_list]

    # Write to JSON file
    with open('jprobe_data.json', 'w') as f:
        json.dump(probe_list_dictionary, f, indent=4)

    print("write complete")


def read_data():
    # Read from JSON file
    with open('jprobe_data.json', 'r') as f:
        probe_list_dicts = json.load(f)

    # Convert dictionaries back to JProbe objects
    return [JQueryProbe(**probe_dict) for probe_dict in probe_list_dicts]


def get_file_hash(url):
    try:
        # Send a GET request to fetch the JavaScript file from the URL
        response = requests.get(url)
        if response.status_code == 200:
            # Read the content of the file
            js_content = response.content

            # Get the SHA-256 hash of the file content
            sha256_hash = hashlib.sha256(js_content).hexdigest()

            return sha256_hash

        else:
            print(f"Failed to fetch JavaScript file from {url}. Status code: {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error fetching JavaScript file from {url}: {e}")
        return None


def detect_jquery_type(url):
    try:
        # Make a GET request to fetch the JavaScript file from the URL
        response = requests.get(url)
        if response.status_code == 200:
            # Split the content into lines and take the first two lines
            lines = response.text.splitlines()
            first_two_lines = lines[:2] # <- The first two lines

            # Calculate the length of each line
            lengths = [len(line) for line in first_two_lines]
            version = None
            if lengths[0] < 5:
                index = first_two_lines[1].find("jQuery")
                if index != -1:
                    #find version 
                    pattern = r'v\d\.\d{1,2}\.\d'
                    version = re.findall(pattern, first_two_lines[1])
                    #print(f'the version is {version}')
                    #print("line 2")
                    #print(first_two_lines[1])
                else:
                    version = re.findall(pattern, first_two_lines[0])
                    #print(f'the version is {version}')
                    #print("line 1")
                    #print(first_two_lines[0])

            return version
        else:
            print(f"Failed to fetch URL. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while getting the version: {e}")


def get_js_script_tags(url):
    # Send a GET request to the URL
    response = requests.get(url)
    
    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content with BeautifulSoup (I prefer burgers)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find all script tags with src attribute ending in .js
        script_tags = soup.find_all('script', src=lambda s: s and s.endswith('.js'))
        
        # Filter out script tags with relative URLs and construct absolute URLs
        absolute_script_tags = []
        for script in script_tags:
            src = script.get('src')
            if src.startswith('http'):
                absolute_script_tags.append(src)
            else:
                absolute_script_tags.append(urljoin(url, src))
        
        # Return the list of absolute URLs of script tags ending in .js
        return absolute_script_tags
    else:
        # Print an error message if request fails
        print(f"Error fetching {url}: Status Code {response.status_code}")

# Example usage:
if __name__ == "__main__":
    url = 'https://mydsu.dsu.edu/'  # Replace with the URL you want to fetch
    js_script_tags = get_js_script_tags(url)
    probes = []
        
    if js_script_tags:
        print(f"Found {len(js_script_tags)} JavaScript files on {url}:")
        for js_file in js_script_tags:
            jq_probe = obj = JQueryProbe(url,'', '', str(todays_date), js_file, False)
            jq_probe.detected_version = detect_jquery_type(js_file)
            jq_probe.script_hash = get_file_hash(js_file)
            probes.append(jq_probe)
            print(f'URL: {jq_probe.probed_url} \nDetected Version: {jq_probe.detected_version}\nScript Hash: {jq_probe.script_hash}\nScript URL: {jq_probe.script_url}')
            
        write_data(probes)
    else:
        print(f"No JavaScript files found on {url}")