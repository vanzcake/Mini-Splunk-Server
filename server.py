import socket
import re
import threading

# Centralized, in-memory storage structure 
indexed_logs = []
# Lock to ensure safe reading/writing when you add concurrency later [cite: 14, 85]
rw_lock = threading.RLock()

# Basic regex to extract Timestamp, Hostname, Process, Severity, Message 
# Note: Real syslog regexes can get complex; this is a simplified version for the prototype.
LOG_PATTERN = re.compile(r"^(?P<timestamp>[a-zA-Z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s*(?:(?P<severity>ERROR|WARN|INFO|DEBUG)\s*:?\s*)?(?P<message>.*)$")

def send_message(sock, message: str):
    encoded = message.encode('utf-8')
    header = f"{len(encoded):010d}|".encode('utf-8')
    sock.sendall(header + encoded)
 
def recv_message(sock) -> str:
    # Step 1: Read exactly 11 bytes (10-digit length + '|')
    header_data = b""
    while len(header_data) < 11:
        chunk = sock.recv(11 - len(header_data))
        if not chunk:
            raise ConnectionError("Connection closed during header read")
        header_data += chunk
 
    msg_len = int(header_data[:10])
 
    # Step 2: Read exactly msg_len bytes for the body
    body = b""
    while len(body) < msg_len:
        chunk = sock.recv(min(4096, msg_len - len(body)))
        if not chunk:
            raise ConnectionError("Connection closed during body read")
        body += chunk
 
    return body.decode('utf-8')

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
    host = '127.0.0.1'
    port = 65432
 
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Avoid "Address already in use" on restart
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[Server] Listening on {host}:{port}")
 
    conn, addr = server_socket.accept()
    print(f"[Server] Connected by {addr}")
 
    while True:
        try:
            data = recv_message(conn)
            if not data:
                break
 
            parts = data.split('|', 2)
            action = parts[0]
 
            if action == "UPLOAD":
                filesize = int(parts[1])
                file_content = parts[2]
                count = parse_and_store(file_content)
                send_message(conn, f"SUCCESS: File received and {count} syslog entries parsed and indexed.")
 
            elif action == "QUERY":
                sub_command = parts[1]
                query_value = parts[2]
                response = handle_query(sub_command, query_value)
                send_message(conn, response)
 
            elif action == "ADMIN":
                admin_cmd = parts[1]
                if admin_cmd == "PURGE":
                    with rw_lock:
                        count = len(indexed_logs)
                        indexed_logs.clear()
                    send_message(conn, f"SUCCESS: {count} indexed log entries have been erased.")
                elif admin_cmd == "QUIT":
                    print("[Server] Client requested disconnection.")
                    break
 
        except ConnectionError as e:
            print(f"[Server] Connection lost: {e}")
            break
        except Exception as e:
            print(f"[Server] Error: {e}")
            break
 
    conn.close()
    server_socket.close()
    print("[Server] Shut down.")
 
if __name__ == "__main__":
    start_server()