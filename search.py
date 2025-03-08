import time
import requests
from urllib.parse import quote
import tldextract

def extract_root_domain(mx_record: str) -> str:
    """Extract root domain from MX record with basic validation"""
    extracted = tldextract.extract(mx_record)
    if not extracted.suffix:
        raise ValueError("Invalid MX record format")
    return f"{extracted.domain}.{extracted.suffix}"

def generate_google_dorks(root_domain: str) -> list:
    """Generate list of Google dork queries for login pages"""
    base_queries = [
        f'site:{root_domain} inurl:login',
        f'site:{root_domain} inurl:signin',
        f'site:{root_domain} intitle:"login"',
        f'site:{root_domain} intext:"username" intext:"password"',
        f'site:{root_domain} inurl:/admin',
        f'site:{root_domain} inurl:/webmail',
        f'site:{root_domain} inurl:/owa',
        f'site:{root_domain} inurl:/cpanel',
        f'site:{root_domain} inurl:"/wp-login.php"',
        f'site:{root_domain} "powered by Roundcube"'
    ]
    return base_queries

def google_search(query: str, api_key: str, cx: str, delay: float = 1.0) -> list:
    """Perform Google search using Custom Search JSON API"""
    time.sleep(delay)  # Simple rate limiting
    endpoint = "https://www.googleapis.com/customsearch/v1"
    params = {
        'q': query,
        'key': api_key,
        'cx': cx,
        'num': 5  # Max results per request
    }
    
    try:
        response = requests.get(endpoint, params=params)
        response.raise_for_status()
        results = response.json()
        return [item['link'] for item in results.get('items', [])]
    except requests.exceptions.RequestException as e:
        print(f"Search failed for {query}: {str(e)}")
        return []
    except ValueError as e:
        print(f"Failed to parse JSON for {query}: {str(e)}")
        return []

def find_login_pages(mx_record: str, api_key: str, cx: str) -> list:
    """Main function to find login pages from MX record"""
    try:
        root_domain = extract_root_domain(mx_record)
    except ValueError as e:
        print(f"Invalid MX record: {str(e)}")
        return []
    
    dork_queries = generate_google_dorks(root_domain)
    found_urls = []
    
    for query in dork_queries:
        print(f"Searching: {query}")
        results = google_search(query, api_key, cx)
        found_urls.extend(results)
        time.sleep(2)  # Add delay between searches
    
    # Simple duplicate removal
    unique_urls = []
    seen = set()
    for url in found_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls

# Example usage
if __name__ == "__main__":
    # Replace with your Google API credentials
    GOOGLE_API_KEY = "AIzaSyB-HW5M93C32osNEZwTuiwtTqQN5mspLko"
    GOOGLE_CX = "c6d03b84830cd4478"
    
    mx_record = "gmail-smtp-in.l.google.com"  # Replace with your MX record
    
    print(f"Searching for login pages associated with {mx_record}")
    login_pages = find_login_pages(mx_record, GOOGLE_API_KEY, GOOGLE_CX)
    
    print("\nPotential login pages found:")
    for idx, url in enumerate(login_pages, 1):
        print(f"{idx}. {url}")