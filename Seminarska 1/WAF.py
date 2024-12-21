import re
import socket
import threading
import json
from urllib.parse import parse_qs, urlparse, unquote
from datetime import datetime

LOG_ACTION_FILE = "./logs/waf_action-trigered.log"
LOG_RULE_FILE = "./logs/waf_rule-triggered.log"

def load_config(config_file):
    """Load configuration (threshold and rules), from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
            threshold = config.get("threshold", 10)  # Default threshold is 10
            rules = config.get("rules", [])
            print(f"[+] Loaded {len(rules)} rules with threshold {threshold} from {config_file}")
            return rules, threshold
    except Exception as e:
        print(f"[!] Failed to load configuration: {e}")
        return [], 0

def parse_request_params(request):
    """Extract query parameters from an HTTP request."""
    try:
        lines = request.split("\r\n")
        first_line = lines[0]
        method, url, _ = first_line.split()

        if method in ["GET", "POST"]:
            # urlparse parses the url into: scheme, netloc, url, params, query, fragment.
            # querry contains user payload which needs to be inspected
            query = urlparse(url).query  
            if method == "POST": # Post can contain multiple parameters in the body
                for line in lines:
                    if line == "":  # Body starts after an empty line
                        body_index = lines.index(line) + 1 
                        body = "&".join(lines[body_index:])
                        query += "&" + body
                        break
            # uniqote -> replaces escapes by their single cahracter,
            # by default, percent-encoded sequences are decoded with UTF-8, and invalid sequences are replaced by a placeholder character.
            # parse_qs -> returns a dictionary (list of touples), where values are user requests to server
            # Example:    "input=SELECT+*+FROM+users+WHERE+id=1;<script>alert('XSS')</script>"
            # Parses into: {'input': ['SELECT * FROM users WHERE id=1;<script>alert(\'XSS\')</script>']}
            return parse_qs(unquote(query))
    except Exception as e:
        print(f"[!] Failed to parse request parameters: {e}")
    return {}

def inspect_request(client_address, request, rules):
    """Inspect HTTP request parameters against the loaded rules."""
    params = parse_request_params(request)
    triggered_rules = []
    total_anomaly_score = 0

    for rule in rules:
        if rule["target"] == "ARGS":
            for key, values in params.items():
                for value in values:
                    # re.search -> Tries matching the pattern with the given value
                    if re.search(rule["pattern"], value, re.IGNORECASE):
                        triggered_rules.append(rule)
                        total_anomaly_score += rule.get("anomaly_score", 0)
                        log_action(client_address, request, rule, LOG_RULE_FILE)

    return triggered_rules, total_anomaly_score

# Function to log actions to a file
def log_action(client_address, request, rule, LOG_FILE):
    """Log the triggered rule and action to a log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"{timestamp} | Rule {rule['id']} | Client {client_address[0]}:{client_address[1]} | "
        f"Action: {rule['action']} | Request: {request.strip()}\n"
    )
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(log_entry)
        print(f"[+] Log entry added: {log_entry.strip()}")
    except Exception as e:
        print(f"[!] Failed to write log entry: {e}")

# Function to handle actions
def action_handler(triggered_rules, client_socket, client_address, request):
    """Handle actions based on the triggered rules."""
    if not triggered_rules:
        return False

    # Determine the most severe action
    severity_order = ["drop", "deny", "allow"]
    most_severe_action = next((rule["action"] for rule in triggered_rules if rule["action"] in severity_order), "allow")

    # Log all triggered rules
    for rule in triggered_rules:
        log_action(client_address, request, rule, LOG_ACTION_FILE)

    # Execute the most severe action
    if most_severe_action == "deny":
        response = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 9\r\n\r\n"
            "Forbidden"
        )
        client_socket.sendall(response.encode('utf-8'))
        return True
    elif most_severe_action == "drop":
        client_socket.close()
        print(f"[!] Connection dropped with client {client_address}.")
        return True

    return False

# Function to handle client connections
def handle_client(client_socket, client_address, rules, threshold, server_socket):
    try:
        while True:
            request = client_socket.recv(4096).decode('utf-8')
            if not request:
                break  # Client disconnected

            print(f"[*] Request from {client_address}: {request}")

            # Inspect the request
            triggered_rules, total_anomaly_score = inspect_request(client_address, request, rules)
            print(f"[+] Total Anomaly Score: {total_anomaly_score}")

            if total_anomaly_score >= threshold:
                print(f"[!] Anomaly score exceeded threshold ({threshold}). Executing action.")
                if action_handler(triggered_rules, client_socket, client_address, request):
                    break
            else:
                # Send request to server and return response to client
                server_socket.sendall(request.encode('utf-8'))

                server_response = server_socket.recv(4096)

                client_socket.sendall(server_response)

    except Exception as e:
        print(f"[!] Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"[*] Connection with {client_address} closed.")

# Main server
def main():
    waf_IP = 'localhost'
    waf_PORT = 8080

    server_IP = 'localhost'
    server_PORT = 9998

    # Load configuration
    config_file = "rules.json"
    rules, threshold = load_config(config_file)

    # Create server TCP socket
    waf_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    waf_socket.bind((waf_IP, waf_PORT))
    waf_socket.listen(5)

    # Connect with server TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((server_IP, server_PORT))
    
    print(f"[*] WAF Listening on {waf_IP}:{waf_PORT} with threshold {threshold}")

    while True:
        client_socket, client_address = waf_socket.accept()
        print(f"[*] Connection from {client_address[0]}:{client_address[1]}")

        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address, rules, threshold, server_socket))
        client_handler.start()

if __name__ == '__main__':
    main()
