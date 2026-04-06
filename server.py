import socket
import re
import threading

# Centralized, in-memory storage structure
indexed_logs = []
# RLock allows the same thread to acquire the lock multiple times (reentrant)
rw_lock = threading.RLock()

# Syslog regex: captures Timestamp, Hostname, Process, and Message.
# Severity is NOT reliably embedded in the syslog header — it is inferred from the message body.
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>[a-zA-Z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[\d+\])?:\s*"
    r"(?P<message>.*)$"
)

# Severity keywords to scan for inside the message body
SEVERITY_LEVELS = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARN", "WARNING", "NOTICE", "INFO", "DEBUG"]

def infer_severity(message: str) -> str | None:
    """Scan the message text for a known severity keyword and return it (uppercased), or None."""
    msg_upper = message.upper()
    for level in SEVERITY_LEVELS:
        # Match whole-word severity tokens to avoid false positives (e.g. "information")
        if re.search(rf'\b{level}\b', msg_upper):
            # Normalize WARN/WARNING and CRITICAL aliases
            if level == "WARNING":
                return "WARN"
            return level
    return None


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


def parse_and_store(log_data: str) -> int:
    """Parse raw syslog text and store structured entries. Returns count of parsed lines."""
    global indexed_logs
    count = 0
    with rw_lock:
        for line in log_data.splitlines():
            if not line.strip():
                continue
            match = LOG_PATTERN.match(line)
            if match:
                entry = match.groupdict()
                # FIX: Severity is inferred from the message body, not the header
                entry['severity'] = infer_severity(entry['message'])
                indexed_logs.append(entry)
                count += 1
    return count


def handle_query(command: str, value: str) -> str:
    """Execute a search/count query against the indexed logs and return a formatted response."""
    with rw_lock:
        # COUNT_KEYWORD: return aggregate count, not individual lines
        if command == "COUNT_KEYWORD":
            count = sum(1 for log in indexed_logs if value.lower() in log['message'].lower())
            return f"The keyword '{value}' appears in {count} indexed log entry/entries."

        results = []
        for log in indexed_logs:
            if command == "SEARCH_DATE":
                # FIX: Strip extra whitespace in timestamp before comparison
                if log['timestamp'].strip().startswith(value.strip()):
                    results.append(log)
            elif command == "SEARCH_HOST":
                if log['hostname'].lower() == value.lower():
                    results.append(log)
            elif command == "SEARCH_DAEMON":
                if value.lower() in log['process'].lower():
                    results.append(log)
            elif command == "SEARCH_SEVERITY":
                # FIX: log['severity'] may be None; guard against that before comparing
                log_sev = log['severity']
                if log_sev is not None and log_sev.upper() == value.upper():
                    results.append(log)
            elif command == "SEARCH_KEYWORD":
                if value.lower() in log['message'].lower():
                    results.append(log)

        if not results:
            return f"No matching entries found for '{value}'."

        output = [f"Found {len(results)} matching entries for '{value}':"]
        for i, log in enumerate(results, 1):
            sev = f"[{log['severity']}] " if log['severity'] else ""
            output.append(
                f"{i}. {log['timestamp']} {log['hostname']} {log['process']}: {sev}{log['message']}"
            )
        return "\n".join(output)


def handle_client(conn, addr):
    """Handle all commands from a single connected client."""
    print(f"[Server] Connected by {addr}")
    try:
        while True:
            data = recv_message(conn)
            if not data:
                break

            parts = data.split('|', 2)
            action = parts[0]

            if action == "UPLOAD":
                if len(parts) < 3:
                    send_message(conn, "ERROR: Malformed UPLOAD request.")
                    continue
                file_content = parts[2]
                count = parse_and_store(file_content)
                send_message(conn, f"SUCCESS: File received and {count} syslog entries parsed and indexed.")

            elif action == "QUERY":
                if len(parts) < 3:
                    send_message(conn, "ERROR: Malformed QUERY request.")
                    continue
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
                    print(f"[Server] Client {addr} requested disconnection.")
                    break

            else:
                send_message(conn, f"ERROR: Unknown action '{action}'.")

    except ConnectionError as e:
        print(f"[Server] Connection lost ({addr}): {e}")
    except Exception as e:
        print(f"[Server] Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[Server] Connection closed for {addr}")


def start_server():
    host = '127.0.0.1'
    port = 65432

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[Server] Listening on {host}:{port}")

    # FIX: Loop to accept multiple clients (each in their own thread)
    try:
        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()