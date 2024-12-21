import socket

# Server
def main():
    IP = 'localhost'
    PORT = 9998
    # AF_INET -> adress family IPv4
    # SOCK_STREAM -> socket type TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen(1) # Only one conection available at a time
    print(f"[*] Listening on {IP}:{PORT}")

    while True:
        client_socket, adress = server_socket.accept()
        print(f"[*] Accepted connection from {adress[0]}:{adress[1]}")

        while True: # If user ends connection stop the loop
            request = client_socket.recv(1024).decode('utf-8')
            
            if not request:
                break # WAF disconected
           
            print(f"[*] Request: {request}")

            if request.strip().lower() == "quit":
                print("[*] Client request to close the connection.")
                break
            
            # Send responce
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 17\r\n\r\n"
                "Request accepted!"
            )

            client_socket.sendall(response.encode('utf-8'))

        client_socket.close()
        print("[*] Connection closed.")
        break

if __name__ == '__main__':
    main()