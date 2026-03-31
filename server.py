import socket
import re
import threading

# Centralized, in-memory storage structure 
indexed_logs = []
# Lock to ensure safe reading/writing when you add concurrency later [cite: 14, 85]
rw_lock = threading.Lock()

# Basic regex to extract Timestamp, Hostname, Process, Severity, Message 
# Note: Real syslog regexes can get complex; this is a simplified version for the prototype.
LOG_PATTERN = re.compile(r"^(?P<timestamp>[a-zA-Z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s*(?:(?P<severity>ERROR|WARN|INFO|DEBUG)\s*:?\s*)?(?P<message>.*)$")

def parse_and_store(log_data):
    global indexed_logs
    count = 0
    with rw_lock: # Acquire write lock
        for line in log_data.splitlines():
            if not line.strip(): continue
            match = LOG_PATTERN.match(line)
            if match:
                indexed_logs.append(match.groupdict())
                count += 1
    return count

def handle_query(command, value):
    with rw_lock: # Acquire read lock
        results = []
        for log in indexed_logs:
            if command == "SEARCH_DATE" and log['timestamp'].startswith(value):
                results.append(log)
            elif command == "SEARCH_HOST" and log['hostname'] == value:
                results.append(log)
            elif command == "SEARCH_DAEMON" and value in log['process']:
                results.append(log)
            elif command == "SEARCH_SEVERITY" and log['severity'] == value:
                results.append(log)
            elif command == "SEARCH_KEYWORD" and value in log['message']:
                results.append(log)
            
        if command == "COUNT_KEYWORD":
            count = sum(1 for log in indexed_logs if value in log['message'])
            return f"The keyword '{value}' appears in {count} indexed log entry/entries."
            
        # Format the output for standard searches
        if not results:
            return "No matching entries found."
        
        output = [f"Found {len(results)} matching entries:"]
        for i, log in enumerate(results, 1):
            sev = f"{log['severity']}: " if log['severity'] else ""
            output.append(f"{i}. {log['timestamp']} {log['hostname']} {log['process']}: {sev}{log['message']}")
        return "\n".join(output)

def start_server():
    global indexed_logs
    host = '127.0.0.1'
    port = 65432

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    while True:
        try:
            # Note: 4096 might be too small for massive files; we'll keep it simple for now
            data = conn.recv(40960).decode('utf-8') 
            if not data:
                break

            parts = data.split('|', 2)
            action = parts[0]

            if action == "UPLOAD":
                filesize = int(parts[1])
                file_content = parts[2]
                count = parse_and_store(file_content)
                conn.sendall(f"SUCCESS: File received and {count} syslog entries parsed and indexed.".encode('utf-8'))

            elif action == "QUERY":
                sub_command = parts[1]
                query_value = parts[2]
                response = handle_query(sub_command, query_value)
                conn.sendall(response.encode('utf-8'))

            elif action == "ADMIN":
                admin_cmd = parts[1]
                if admin_cmd == "PURGE":
                    with rw_lock: # Acquire exclusive write lock [cite: 85]
                        indexed_logs.clear()
                    conn.sendall("SUCCESS: All indexed log entries have been erased.".encode('utf-8'))
                elif admin_cmd == "QUIT":
                    print("Client requested termination.")
                    break

        except Exception as e:
            print(f"Error: {e}")
            break

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()