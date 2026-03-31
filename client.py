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
                    client_socket.sendall(protocol_string.encode('utf-8'))
                    print(f"[System Message] Uploading syslog ({filesize} bytes)...")
                    response = client_socket.recv(4096).decode('utf-8')
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
                client_socket.sendall(protocol_string.encode('utf-8'))
                print("[System Message] Sending query...")
                response = client_socket.recv(4096).decode('utf-8')
                print(f"[Server Response] {response}")

            elif base_cmd == "PURGE":
                protocol_string = "ADMIN|PURGE"
                client_socket.sendall(protocol_string.encode('utf-8'))
                print(f"[System Message] Connecting to {host}:{port} to purge records... [cite: 88]")
                response = client_socket.recv(4096).decode('utf-8')
                print(f"[Server Response] {response}")

            elif base_cmd == "QUIT":
                protocol_string = "ADMIN|QUIT"
                client_socket.sendall(protocol_string.encode('utf-8'))
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