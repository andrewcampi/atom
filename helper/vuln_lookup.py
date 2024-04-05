import requests
import re
import json
from bs4 import BeautifulSoup
from helper.general_helpers import write_json


def get_exploitdb_link(scraper, search_url):
    response = scraper.get(search_url)
    page_content = response.text
    
    # Define the regular expression pattern to match the desired section
    pattern = r'<div class="tptxt"><div class="tptt">Exploit Database</div>.*?<cite>(.*?)</cite>'
    
    # Search for the pattern in the page content
    match = re.search(pattern, page_content, re.DOTALL)
    
    if match:
        # Extract the URL from the matched group
        url = match.group(1)
        
        # Remove any HTML tags from the URL
        url = re.sub(r'<.*?>', '', url)
        
        if not url.startswith("https://"):
            url = "https://" + url
            
        return url
    else:
        return None


def exploitdb_page_to_json(scraper, link):
    page_content = scraper.get(link).text
    exploit_db_data = {}

    # Extract title
    title_pattern = r'<h1 class="card-title text-secondary text-center" style="font-size: 2.5em;">\s*(.*?)\s*</h1>'
    title_match = re.search(title_pattern, page_content, re.DOTALL)
    if title_match:
        exploit_db_data["title"] = title_match.group(1).strip()

    # Extract CVE
    cve_pattern = r'<h4 class="info-title">\s*CVE:\s*</h4>\s*<h6 class="stats-title">\s*<a href=".*?" target="_blank">\s*(.*?)\s*</a>\s*</h6>'
    cve_match = re.search(cve_pattern, page_content, re.DOTALL)
    if cve_match:
        exploit_db_data["cve"] = cve_match.group(1).strip()

    # Extract exploit code and language (removing this code to be more mindful of token count)
    """
    code_pattern = r'<pre><code class="language-(\w+)".*?>(.*?)</code></pre>'
    code_match = re.search(code_pattern, page_content, re.DOTALL)
    if code_match:
        exploit_db_data["exploit_code_language"] = code_match.group(1).strip()
        exploit_db_data["exploit_code"] = code_match.group(2).strip()
    """
    return exploit_db_data


def find_most_numbered_substring(s):
    # Find all substrings of s containing numbers and return the one with the most digits
    number_substrings = re.findall(r'\d+', s)
    if not number_substrings:
        return ""
    return max(number_substrings, key=len)


def find_cpes(component, version):
    base_url = "https://nvd.nist.gov/products/cpe/search/results"
    attempts = [
        {"component": component, "version": version},
        {"version": find_most_numbered_substring(version)},  # Adjust version for 2nd attempt
        {"component": component.split()[0], "version": find_most_numbered_substring(version)}  # Adjust component for 3rd attempt
    ]

    for attempt in attempts:
        params = {
            "namingFormat": "2.3",
            "keyword": f'{attempt.get("component", component)} {attempt.get("version", version)}'
        }
        response = requests.get(base_url, params=params)
        content = response.text

        cpe_matches = re.findall(r'cpe:2\.3:[^<]*', content)
        if cpe_matches:  # If matches found, return them
            # Extracting the unique part of the CPE match, removing HTML tags or entities
            to_return = []
            cpe_matches = [re.sub(r'<[^>]+>', '', match) for match in cpe_matches]
            for match in cpe_matches:
                if match.endswith(":*"):
                    to_return.append(match)
            return to_return

    return []

def fetch_cve_details(cpe_strings):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    all_cve_details = []

    for cpe_string in cpe_strings:
        url = f"{base_url}?cpeName={cpe_string}"

        response = requests.get(url)

        if response.status_code != 200:
            print(f"Error: Unable to retrieve CVE data for CPE: {cpe_string}. Status code: {response.status_code}")
            continue
        
        data = response.json()
        
        for cve_item in data["vulnerabilities"]:
            cve_id = cve_item["cve"]["id"]
            description_text = cve_item["cve"]["descriptions"][0]["value"]
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            weaknesses = []
            for problem_type in cve_item["cve"]["weaknesses"]:
                for description in problem_type["description"]:
                    weaknesses.append(description["value"])

            all_cve_details.append({
                "CVE ID": cve_id,
                "Description": description_text,
                "Weaknesses": ", ".join(weaknesses),
                "Link": link,
                "Exploit Status": "Public Exploit Found"
            })

    return all_cve_details


def fetch_github_urls(cve_id):
    api_url = f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}"
    response = requests.get(api_url)

    if response.status_code == 200:
        data = response.json()
        if "pocs" in data and data["pocs"]:
            github_urls = [poc["html_url"] for poc in data["pocs"]]
            return github_urls
    return []

def search_and_extract_download_links(product_name):
    search_url = f"https://packetstormsecurity.com/search/?q={product_name}"
    response = requests.get(search_url)

    download_links = []

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        results = soup.find_all('a', href=True)

        for result in results:
            href = result['href']
            if '/files/download/' in href and href.endswith('.txt'):
                download_links.append(f"https://packetstormsecurity.com{href}")

        if not download_links:
            print("No download links found on Packet Storm Security.")
            return None

    return download_links