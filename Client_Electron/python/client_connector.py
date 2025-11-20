import sys
import json
import urllib.request
import urllib.error

# --- CONFIGURATION ---
# If running locally for testing, use localhost. 
# If running on remote, use that IP.
SERVER_URL = "http://192.168.2.234:3000" 

def make_request(endpoint, method, payload=None):
    url = f"{SERVER_URL}{endpoint}"
    headers = {'Content-Type': 'application/json'}
    data = json.dumps(payload).encode('utf-8') if payload else None

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req) as response:
            # Read response
            result = response.read().decode('utf-8')
            # PRINT ONLY THE RESULT
            sys.stdout.write(result)
            sys.stdout.flush()
            
    except urllib.error.HTTPError as e:
        # The server returned 400/401/500, but usually sends a JSON body (e.g., error message)
        error_content = e.read().decode('utf-8')
        sys.stdout.write(error_content)
        sys.stdout.flush()
        
    except Exception as e:
        # System/Network Error: create a manual JSON error
        error_json = json.dumps({"success": False, "error": str(e)})
        sys.stdout.write(error_json)
        sys.stdout.flush()

if __name__ == "__main__":
    # Force UTF-8 encoding for stdout to prevent Windows crashing on emojis
    if sys.platform == "win32":
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    method = sys.argv[1]
    endpoint = sys.argv[2]
    
    payload = None
    if len(sys.argv) > 3:
        try:
            payload = json.loads(sys.argv[3])
        except:
            pass

    make_request(endpoint, method, payload)