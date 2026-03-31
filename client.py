import socket
import os

def print_help():
    print("""
=============================================================================
                          MINI-SPLUNK CLI HELP
=============================================================================
INGEST <file_path>                 : Uploads a local syslog file[cite: 24, 25].
QUERY SEARCH_DATE "<date>"         : Searches logs by date[cite: 32, 33].
QUERY SEARCH_HOST <hostname>       : Searches logs by machine name[cite: 42, 43].
QUERY SEARCH_DAEMON <daemon>       : Searches logs by service name[cite: 51, 52].
QUERY SEARCH_SEVERITY <level>      : Searches by severity (e.g., ERROR)[cite: 59, 60].
QUERY SEARCH_KEYWORD "<keyword>"   : Searches by exact keyword/phrase[cite: 67, 68].
QUERY COUNT_KEYWORD "<keyword>"    : Counts occurrences of a keyword[cite: 75, 76].
PURGE                              : Erases all indexed logs on server[cite: 82, 83].
QUIT                               : Closes the connection.
HELP                               : Displays this menu.
=============================================================================
""")

def send_message(client_socket, message):
    encoded = message.encode('utf-8')
    length = len(encoded)
    # Prepend the length as a fixed 10-digit ASCII number, e.g. "0000000512|<body>"
    header = f"{length:010d}|".encode('utf-8')
    client_socket.sendall(header + encoded)

def recv_message(client_socket) -> str:
    # Step 1: Read exactly 11 bytes to get the length header
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
        print(f"[System Message] Connecting to {host}:{port}...")
        print_help() # Show help menu on successful connection
    except ConnectionRefusedError:
        print("Server is not running.")
        return

    while True:
        try:
            user_input = input("client> ").strip()
            if not user_input:
                continue
                
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
                    # Read local file and stream to server [cite: 26]
                    with open(file_path, 'r') as f:
                        content = f.read()
                    filesize = len(content)
                    protocol_string = f"UPLOAD|{filesize}|{content}"
                    # old
                    #client_socket.sendall(protocol_string.encode('utf-8'))
                    send_message(client_socket, protocol_string) # Use the new send_message function
                    print(f"[System Message] Uploading syslog ({filesize} bytes)...")
                    response = recv_message(client_socket)
                    print(f"[Server Response] {response}")
                except FileNotFoundError:
                    print(f"File not found: {file_path}")

            elif base_cmd == "QUERY":
                if len(command_input) < 3:
                    print("Usage: QUERY <SEARCH_TYPE> <value>")
                    continue
                search_type = command_input[1].upper()
                value = command_input[2].strip('"') # Remove quotes if user typed them
                
                protocol_string = f"QUERY|{search_type}|{value}"
                send_message(client_socket, protocol_string)
                print("[System Message] Sending query...")
                response = recv_message(client_socket)
                print(f"[Server Response] {response}")

            elif base_cmd == "PURGE":
                protocol_string = "ADMIN|PURGE"
                send_message(client_socket, protocol_string)
                print(f"[System Message] Connecting to {host}:{port} to purge records... [cite: 88]")
                response = recv_message(client_socket)
                print(f"[Server Response] {response}")

            elif base_cmd == "QUIT":
                protocol_string = "ADMIN|QUIT"
                send_message(client_socket, protocol_string)
                print("Closing connection.")
                break
            
            else:
                if base_cmd != "HELP":
                    print("Unknown command. Type HELP to see available commands.")

        except Exception as e:
            print(f"Client error: {e}")
            break

    client_socket.close()

if __name__ == "__main__":
    start_client()