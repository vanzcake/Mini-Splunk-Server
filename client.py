import socket


def print_help():
    print("""
=============================================================================
                          MINI-SPLUNK CLI HELP
=============================================================================
INGEST <file_path> <IP>:<Port>         : Uploads a local syslog file to the server.
QUERY <IP>:<Port> SEARCH_DATE "<date>" : Searches logs by date (e.g., "Feb 22").
QUERY <IP>:<Port> SEARCH_HOST <host>   : Searches logs by machine name.
QUERY <IP>:<Port> SEARCH_DAEMON <name> : Searches logs by service/process name.
QUERY <IP>:<Port> SEARCH_SEVERITY <lvl>: Searches by severity (ERROR, WARN, INFO...).
QUERY <IP>:<Port> SEARCH_KEYWORD "<kw>": Searches by keyword or phrase in message body.
QUERY <IP>:<Port> COUNT_KEYWORD "<kw>" : Counts occurrences of a keyword.
PURGE <IP>:<Port>                      : Erases all indexed logs on the server.
QUIT                                   : Exits the CLI.
HELP                                   : Displays this menu.
=============================================================================
""")


def parse_address(addr_str: str):
    """Parse 'IP:Port' string into (host, port). Raises ValueError on bad format."""
    try:
        host, port_str = addr_str.rsplit(":", 1)
        return host, int(port_str)
    except ValueError:
        raise ValueError(f"Invalid address format '{addr_str}'. Expected <IP>:<Port>.")


def send_message(sock, message: str):
    encoded = message.encode('utf-8')
    length = len(encoded)
    header = f"{length:010d}|".encode('utf-8')
    sock.sendall(header + encoded)


def recv_message(sock) -> str:
    # Read exactly 11 bytes: 10-digit length + '|'
    header = b""
    while len(header) < 11:
        chunk = sock.recv(11 - len(header))
        if not chunk:
            raise ConnectionError("Socket closed before header complete")
        header += chunk

    msg_len = int(header[:10].strip())

    # Read exactly msg_len bytes for the body
    body = b""
    while len(body) < msg_len:
        chunk = sock.recv(msg_len - len(body))
        if not chunk:
            raise ConnectionError("Socket closed before body complete")
        body += chunk

    return body.decode('utf-8')


def open_connection(host: str, port: int):
    """Open a TCP connection to the given host:port. Returns the socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


def do_request(host: str, port: int, protocol_string: str) -> str:
    """
    Open a fresh connection, send one protocol message, receive the response,
    then close the connection. Returns the server's response string.
    """
    sock = open_connection(host, port)
    try:
        send_message(sock, protocol_string)
        return recv_message(sock)
    finally:
        sock.close()


def start_client():
    print_help()

    while True:
        try:
            user_input = input("client> ").strip()
            if not user_input:
                continue

            parts = user_input.split(" ", 3)
            base_cmd = parts[0].upper()

            # ------------------------------------------------------------------
            # HELP — local only, no network
            # ------------------------------------------------------------------
            if base_cmd == "HELP":
                print_help()

            # ------------------------------------------------------------------
            # QUIT — local only
            # ------------------------------------------------------------------
            elif base_cmd == "QUIT":
                print("[System Message] Exiting.")
                break

            # ------------------------------------------------------------------
            # INGEST <file_path> <IP>:<Port>
            # ------------------------------------------------------------------
            elif base_cmd == "INGEST":
                # parts: ['INGEST', '<file_path>', '<IP>:<Port>']
                if len(parts) < 3:
                    print("Usage: INGEST <file_path> <IP>:<Port>")
                    continue

                file_path = parts[1]
                addr_str  = parts[2]

                try:
                    host, port = parse_address(addr_str)
                except ValueError as e:
                    print(f"[Error] {e}")
                    continue

                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    filesize = len(content.encode('utf-8'))
                    protocol_string = f"UPLOAD|{filesize}|{content}"

                    print(f"[System Message] Connecting to {host}:{port}...")
                    print(f"[System Message] Uploading syslog ({filesize} bytes)...")
                    response = do_request(host, port, protocol_string)
                    print(f"[Server Response] {response}")

                except FileNotFoundError:
                    print(f"[Error] File not found: {file_path}")

            # ------------------------------------------------------------------
            # QUERY <IP>:<Port> <SEARCH_TYPE> <value>
            # ------------------------------------------------------------------
            elif base_cmd == "QUERY":
                # parts: ['QUERY', '<IP>:<Port>', '<SEARCH_TYPE>', '<value>']
                if len(parts) < 4:
                    print("Usage: QUERY <IP>:<Port> <SEARCH_TYPE> <value>")
                    print("Example: QUERY 127.0.0.1:65432 SEARCH_SEVERITY ERROR")
                    continue

                addr_str    = parts[1]
                search_type = parts[2].upper()
                value       = parts[3].strip().strip('"').strip("'")

                try:
                    host, port = parse_address(addr_str)
                except ValueError as e:
                    print(f"[Error] {e}")
                    continue

                if not value:
                    print("[Error] Query value cannot be empty.")
                    continue

                valid_queries = {
                    "SEARCH_DATE", "SEARCH_HOST", "SEARCH_DAEMON",
                    "SEARCH_SEVERITY", "SEARCH_KEYWORD", "COUNT_KEYWORD"
                }
                if search_type not in valid_queries:
                    print(f"[Error] Unknown query type '{search_type}'. "
                          f"Valid types: {', '.join(sorted(valid_queries))}")
                    continue

                protocol_string = f"QUERY|{search_type}|{value}"
                print("[System Message] Sending query...")
                response = do_request(host, port, protocol_string)
                print(f"[Server Response] {response}")

            # ------------------------------------------------------------------
            # PURGE <IP>:<Port>
            # ------------------------------------------------------------------
            elif base_cmd == "PURGE":
                # parts: ['PURGE', '<IP>:<Port>']
                if len(parts) < 2:
                    print("Usage: PURGE <IP>:<Port>")
                    continue

                addr_str = parts[1]

                try:
                    host, port = parse_address(addr_str)
                except ValueError as e:
                    print(f"[Error] {e}")
                    continue

                protocol_string = "ADMIN|PURGE"
                print(f"[System Message] Connecting to {host}:{port} to purge records...")
                response = do_request(host, port, protocol_string)
                print(f"[Server Response] {response}")

            else:
                print("Unknown command. Type HELP to see available commands.")

        except KeyboardInterrupt:
            print("\n[System Message] Interrupted. Exiting.")
            break
        except ConnectionRefusedError as e:
            print(f"[Error] Could not connect to server: {e}")
        except Exception as e:
            print(f"[Client Error] {e}")


if __name__ == "__main__":
    start_client()