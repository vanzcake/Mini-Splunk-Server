import socket
import re
import sys
import threading

# Centralized, in-memory storage structure
indexed_logs = []
# RLock allows the same thread to acquire the lock multiple times (reentrant)
rw_lock = threading.RLock()

# Syslog regex: captures Timestamp, Hostname, Process, and Message.
# Notes:
#   - \s+ in timestamp handles both "Feb  8" (2 spaces, single-digit day) and "Feb 22" (1 space)
#   - process uses [^\s\[:/]+ (greedy, stops at space/bracket/colon) so it correctly
#     captures the full daemon name on lines both with and without a PID bracket:
#       "sshd[1234]:" -> process="sshd"
#       "sshd:"       -> process="sshd"  (non-greedy \S+? only grabbed "s" here before)
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>[a-zA-Z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^\s\[:/]+)(?:\[\d+\])?:\s*"
    r"(?P<message>.*)$"
)

SEVERITY_LEVELS = ["ERROR", "WARN", "WARNING", "INFO", "DEBUG"]
 
# Pre-compiled pattern: matches "error:", "warn:", "warning:", "info:", "debug:"
# at a word boundary, case-insensitive. WARNING is normalised to WARN on return.
_SEVERITY_PATTERN = re.compile(
    r'\b(ERROR|WARN(?:ING)?|INFO|DEBUG)\s*:', re.IGNORECASE
)


def infer_severity(message: str) -> str | None:
    """
    Scan the message for a severity tag in the form 'LEVEL:' (e.g. 'error:').
    Returns the normalised level string (ERROR/WARN/INFO/DEBUG) or None if not found.
    """
    match = _SEVERITY_PATTERN.search(message)
    if match:
        level = match.group(1).upper()
        return level
    return None


def send_message(sock, message: str):
    encoded = message.encode('utf-8')
    header = f"{len(encoded):010d}|".encode('utf-8')
    sock.sendall(header + encoded)


def recv_message(sock) -> str:
    header_data = b""
    while len(header_data) < 11:
        chunk = sock.recv(11 - len(header_data))
        if not chunk:
            raise ConnectionError("Connection closed during header read")
        header_data += chunk

    msg_len = int(header_data[:10])

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
                entry['severity'] = infer_severity(entry['message'])
                indexed_logs.append(entry)
                count += 1
    return count


def handle_query(command: str, value: str) -> str:
    """Execute a search/count query against the indexed logs and return a formatted response."""
    with rw_lock:
        if command == "COUNT_KEYWORD":
            count = sum(1 for log in indexed_logs if value.lower() in log['message'].lower())
            return f"The keyword '{value}' appears in {count} indexed log entry/entries."

        results = []
        for log in indexed_logs:
            if command == "SEARCH_DATE":
                if log['timestamp'].startswith(value):
                    rest = log['timestamp'][len(value):]
                    if rest == "" or rest[0] == " ":
                        results.append(log)
            elif command == "SEARCH_HOST":
                if log['hostname'].lower() == value.lower():
                    results.append(log)
            elif command == "SEARCH_DAEMON":
                if log['process'] == value:
                    results.append(log)
            elif command == "SEARCH_SEVERITY":
                log_sev = log['severity']
                if log_sev is not None and log_sev.upper() == value.upper():
                    results.append(log)
            elif command == "SEARCH_KEYWORD":
                if value.lower() in log['message'].lower():
                    results.append(log)

        if not results:
            return f"No matching entries found for '{value}'."
 
        total = len(results)
        DISPLAY_LIMIT  = 50
        TRUNCATE_AFTER = 300
 
        display = results[:DISPLAY_LIMIT] if total > TRUNCATE_AFTER else results
 
        output = [f"Found {total} matching entries for '{value}':"]
        for i, log in enumerate(display, 1):
            sev = f"[{log['severity']}] " if log['severity'] else ""
            output.append(
                f"{i}. {log['timestamp']} {log['hostname']} {log['process']}: {sev}{log['message']}"
            )
 
        if total > TRUNCATE_AFTER:
            hidden = total - DISPLAY_LIMIT
            output.append(
                f"\n... showing {DISPLAY_LIMIT} of {total} results. "
                f"{hidden} more entries not shown."
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
                    send_message(conn, "ERROR: Malformed INGEST request.")
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

    except ConnectionError:
        print(f"[Server] Client {addr} disconnected.")
    except Exception as e:
        print(f"[Server] Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[Server] Connection closed for {addr}")


def start_server(port: int):
    host = 'localhost'  # Listen on all interfaces so remote clients can connect

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[Server] Listening on {host}:{port}")

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
    if len(sys.argv) < 2:
        print("Usage: python server.py <port>")
        print("Example: python server.py 65432")
        sys.exit(1)

    try:
        server_port = int(sys.argv[1])
    except ValueError:
        print(f"[Error] Invalid port '{sys.argv[1]}'. Must be an integer.")
        sys.exit(1)

    start_server(server_port)