import socket
import os

def print_help():
    print("""
=============================================================================
                          MINI-SPLUNK CLI HELP
=============================================================================
INGEST <file_path>                 : Uploads a local syslog file to the server.
QUERY SEARCH_DATE "<date>"         : Searches logs by date (e.g., "Feb 22").
QUERY SEARCH_HOST <hostname>       : Searches logs by machine name.
QUERY SEARCH_DAEMON <daemon>       : Searches logs by service/process name.
QUERY SEARCH_SEVERITY <level>      : Searches by severity (ERROR, WARN, INFO, DEBUG).
QUERY SEARCH_KEYWORD "<keyword>"   : Searches by keyword or phrase in message body.
QUERY COUNT_KEYWORD "<keyword>"    : Counts occurrences of a keyword.
PURGE                              : Erases all indexed logs on the server.
QUIT                               : Closes the connection.
HELP                               : Displays this menu.
=============================================================================
""")

def send_message(client_socket, message):
    encoded = message.encode('utf-8')
    length = len(encoded)
    # Prepend the length as a fixed 10-digit ASCII number + '|' separator
    header = f"{length:010d}|".encode('utf-8')
    client_socket.sendall(header + encoded)

def recv_message(client_socket) -> str:
    # Step 1: Read exactly 11 bytes to get the length header (10 digits + '|')
    header = b""
    while len(header) < 11:
        chunk = client_socket.recv(11 - len(header))
        if not chunk:
            raise ConnectionError("Socket closed before header complete")
        header += chunk

    msg_len = int(header[:10].strip())

    # Step 2: Read exactly msg_len bytes for the body
    body = b""
    while len(body) < msg_len:
        chunk = client_socket.recv(msg_len - len(body))
        if not chunk:
            raise ConnectionError("Socket closed before body complete")
        body += chunk

    return body.decode('utf-8')

def start_client():
    host = '127.0.0.1'
    port = 65432

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((host, port))
        print(f"[System Message] Connected to {host}:{port}.")
        print_help()
    except ConnectionRefusedError:
        print("[Error] Server is not running. Start server.py first.")
        return

    while True:
        try:
            user_input = input("client> ").strip()
            if not user_input:
                continue

            # Split into at most 3 parts: base_cmd, sub_cmd/arg1, remainder
            command_input = user_input.split(" ", 2)
            base_cmd = command_input[0].upper()

            if base_cmd == "HELP":
                print_help()

            elif base_cmd == "INGEST":
                if len(command_input) < 2:
                    print("Usage: INGEST <file_path>")
                    continue
                file_path = command_input[1]
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    filesize = len(content.encode('utf-8'))
                    # Protocol: UPLOAD|<filesize>|<content>
                    protocol_string = f"UPLOAD|{filesize}|{content}"
                    send_message(client_socket, protocol_string)
                    print(f"[System Message] Uploading syslog ({filesize} bytes)...")
                    response = recv_message(client_socket)
                    print(f"[Server Response] {response}")
                except FileNotFoundError:
                    print(f"[Error] File not found: {file_path}")

            elif base_cmd == "QUERY":
                if len(command_input) < 3:
                    print("Usage: QUERY <SEARCH_TYPE> <value>")
                    print("Example: QUERY SEARCH_SEVERITY ERROR")
                    continue
                search_type = command_input[1].upper()

                # FIX: Strip surrounding quotes the user may have typed (e.g. "Feb 22")
                value = command_input[2].strip().strip('"').strip("'")

                if not value:
                    print("[Error] Query value cannot be empty.")
                    continue

                valid_queries = {
                    "SEARCH_DATE", "SEARCH_HOST", "SEARCH_DAEMON",
                    "SEARCH_SEVERITY", "SEARCH_KEYWORD", "COUNT_KEYWORD"
                }
                if search_type not in valid_queries:
                    print(f"[Error] Unknown query type '{search_type}'. Valid types: {', '.join(sorted(valid_queries))}")
                    continue

                protocol_string = f"QUERY|{search_type}|{value}"
                send_message(client_socket, protocol_string)
                print("[System Message] Sending query...")
                response = recv_message(client_socket)
                print(f"[Server Response] {response}")

            elif base_cmd == "PURGE":
                protocol_string = "ADMIN|PURGE"
                send_message(client_socket, protocol_string)
                print(f"[System Message] Connecting to {host}:{port} to purge records...")
                response = recv_message(client_socket)
                print(f"[Server Response] {response}")

            elif base_cmd == "QUIT":
                protocol_string = "ADMIN|QUIT"
                send_message(client_socket, protocol_string)
                print("[System Message] Closing connection.")
                break

            else:
                print("Unknown command. Type HELP to see available commands.")

        except KeyboardInterrupt:
            print("\n[System Message] Interrupted. Closing connection.")
            break
        except Exception as e:
            print(f"[Client Error] {e}")
            break

    client_socket.close()

if __name__ == "__main__":
    start_client()