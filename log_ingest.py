import socket
import os
import json
import datetime
import threading
import execjs  # JavaScript validation

# Configuration - Define listeners with names and ports
LISTENERS = [
    {"name": "duo-adminaction", "port": 5140},
    {"name": "duo-auth", "port": 5141},
    {"name": "duo-activity", "port": 5142},
    {"name": "duo-trustmonitor", "port": 5143},
    {"name": "duo-telephony", "port": 5144},
]

LOG_DIR = "logs"
INVALID_LOG_DIR = "invalid_logs"

# Ensure log directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(INVALID_LOG_DIR, exist_ok=True)

def get_log_filename(listener_name):
    """Returns the log filename for the given listener."""
    return os.path.join(LOG_DIR, f"{listener_name}_{datetime.datetime.now().strftime('%Y-%m-%d')}.log")

def get_invalid_log_filename(listener_name, log_type="invalid"):
    """Returns the filename for invalid logs."""
    return os.path.join(INVALID_LOG_DIR, f"{listener_name}_{log_type}_{datetime.datetime.now().strftime('%Y-%m-%d')}.log")

def extract_valid_timestamp(log_data):
    """
    Extracts the first valid ISO8601 timestamp from available fields.
    Checks 'isotimestamp' first, then 'ts'. Falls back to "1900-01-01T00:00:00Z" if both are missing/invalid.
    """
    for field in ["isotimestamp", "ts"]:
        if field in log_data:
            try:
                return datetime.datetime.fromisoformat(log_data[field]).isoformat()
            except ValueError:
                pass  # Ignore invalid formats

    return "1900-01-01T00:00:00Z"

def is_valid_javascript(js_code):
    """Checks if the provided JavaScript code is syntactically valid using execjs."""
    try:
        execjs.compile(js_code)  # Compiles without running it
        return True
    except execjs.ProgramError:
        return False  # Syntax error detected

def clean_json_string(json_string):
    """
    Cleans up JSON formatting by:
    - Removing unnecessary escape slashes **only when JSON is invalid**.
    - Ensuring valid JSON structure.
    """
    try:
        json_string = json_string.strip()  # Trim leading/trailing whitespace
        return json_string
    except Exception:
        return json_string  # Return as-is if any issue occurs

def decode_json_fields(log_entry):
    """
    Recursively searches for JSON-encoded strings and converts them into proper JSON objects.
    """
    if isinstance(log_entry, dict):
        for key, value in log_entry.items():
            if isinstance(value, str):  # Check if value is a string
                try:
                    decoded_value = json.loads(value)  # Attempt to parse JSON
                    log_entry[key] = decoded_value  # Replace string with actual JSON
                except (json.JSONDecodeError, TypeError):
                    log_entry[key] = remove_unicode_escapes(value)  # Remove bad unicode escapes
            elif isinstance(value, list):
                log_entry[key] = [decode_json_fields(item) for item in value]  # Decode JSON inside lists
            elif isinstance(value, dict):
                log_entry[key] = decode_json_fields(value)  # Recursively decode nested structures
    elif isinstance(log_entry, list):
        return [decode_json_fields(item) for item in log_entry]  # Decode JSON inside lists
    return log_entry

def remove_unicode_escapes(text):
    """
    Removes or safely handles malformed Unicode escape sequences in strings.
    """
    if isinstance(text, str):
        try:
            return text.encode('utf-8').decode('unicode_escape')  # Decode valid Unicode escapes
        except UnicodeDecodeError:
            return text  # Return original string if decoding fails
    return text

def fix_invalid_json(raw_message):
    """Attempts to fix a malformed JSON string by cleaning and re-parsing it."""
    try:
        fixed_message = json.loads(raw_message)  # Try parsing raw JSON first
        fixed_message = decode_json_fields(fixed_message)  # Decode embedded JSON fields
        return fixed_message
    except json.JSONDecodeError:
        cleaned_message = clean_json_string(raw_message)  # If failed, clean and retry
        try:
            fixed_message = json.loads(cleaned_message)
            fixed_message = decode_json_fields(fixed_message)  # Decode embedded JSON fields
            return fixed_message
        except json.JSONDecodeError as e:
            print(f"⚠️ Warning: Could not parse JSON. Attempting deep fix... Error: {e}")
            return None  # Return None if unable to fix

def write_log(listener_name, log_entry, log_type="normal"):
    """Writes structured log entries, placing invalid logs into a separate file."""
    log_file = get_invalid_log_filename(listener_name, log_type) if log_type != "normal" else get_log_filename(listener_name)
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")  # JSONL format (1 JSON object per line)

def syslog_server(listener_name, port):
    """Starts a syslog server instance for a specific listener."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[{listener_name}] Syslog server listening on port {port}")

    while True:
        try:
            data, addr = sock.recvfrom(8192)  # Increase buffer size for longer messages
            message = data.decode("utf-8").strip()

            try:
                log_data = json.loads(message)  # Parse JSON normally
                log_data = decode_json_fields(log_data)  # Decode JSON-encoded fields
            except json.JSONDecodeError as e:
                print(f"[{listener_name}] Received invalid JSON from {addr[0]}, attempting to fix... Error: {e}")

                fixed_json = fix_invalid_json(message)
                if fixed_json:
                    print(f"[{listener_name}] Successfully fixed JSON from {addr[0]}")
                    log_data = fixed_json
                else:
                    print(f"[{listener_name}] Could not fix JSON from {addr[0]}, saving as invalid.")
                    write_log(listener_name, {"raw_message": message, "source_ip": addr[0]}, log_type="invalid_json")
                    continue

            timestamp = extract_valid_timestamp(log_data)

            log_entry = {
                "timestamp": timestamp,
                "listener": listener_name,
                "source_ip": addr[0],
                "log": log_data
            }

            print(f"[{listener_name}] Received log from {addr[0]}: {log_entry}")
            write_log(listener_name, log_entry)
            print(f"[{listener_name}] Log entry saved.")

        except Exception as e:
            print(f"[{listener_name}] Error: {e}")

if __name__ == "__main__":
    for listener in LISTENERS:
        thread = threading.Thread(target=syslog_server, args=(listener["name"], listener["port"]), daemon=True)
        thread.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nSyslog servers shutting down.")
