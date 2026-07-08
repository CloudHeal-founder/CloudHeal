import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test():
    print("Testing web scanner...")
    url = "http://scanme.nmap.org/"
    try:
        r = requests.get(url, timeout=3, verify=False)
        print(f"Status: {r.status_code}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test()