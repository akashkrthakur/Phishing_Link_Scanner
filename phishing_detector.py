import requests

# Replace with your VirusTotal API key
API_KEY = '545ca6354b7fb9b8b7fd6edceec7b941cea9807d8270b6e6f61ca2c8b8149bce'

def check_phishing(url):
    url = url.strip()

    # Construct the URL for VirusTotal API
    url_scan = f'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_KEY, 'resource': url}

    try:
        # Send GET request to VirusTotal
        response = requests.get(url_scan, params=params)
        response_json = response.json()

        # Check response from VirusTotal
        if response.status_code == 200:
            if response_json['response_code'] == 1:
                # URL has been scanned before
                if response_json['positives'] > 0:
                    return f"Phishing URL (Detected by {response_json['positives']} engines)"
                else:
                    return "Not detected as phishing"
            else:
                return "URL not found in VirusTotal database"
        else:
            return f"Error: {response.status_code} - {response_json.get('verbose_msg', 'Unknown error')}"

    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    # Take input URL from user
    test_url = input("Enter the URL to check: ")

    # Call check_phishing function
    result = check_phishing(test_url)
    print(f"Result for {test_url}: {result}")
