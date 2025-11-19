import sys
import json
import urllib.request
import urllib.error

# Configure this to your Campus Machine IP
SERVER_URL = "http://192.168.1.XXX:3000" 

def make_request(endpoint, method, payload=None):
    url = f"{SERVER_URL}{endpoint}"
    headers = {'Content-Type': 'application/json'}
    data = json.dumps(payload).encode('utf-8') if payload else None

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req) as response:
            print(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        # Return the error from server
        print(e.read().decode('utf-8'))
    except Exception as e:
        print(json.dumps({"success": False, "error": str(e)}))

if __name__ == "__main__":
    # Usage: python client_connector.py <METHOD> <ENDPOINT> <JSON_DATA>
    method = sys.argv[1]
    endpoint = sys.argv[2]
    
    payload = None
    if len(sys.argv) > 3:
        try:
            payload = json.loads(sys.argv[3])
        except:
            pass

    make_request(endpoint, method, payload)