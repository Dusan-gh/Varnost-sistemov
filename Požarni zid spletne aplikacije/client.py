import socket

# Client
def main():
    target_host = "localhost"
    target_port = 8080
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((target_host, target_port))

    while True:
        # Get input from user (MAYBE IT IS AN EXPLOIT) :D
        user_input = input("Enter message (type 'quit' to end):\n")
        if not user_input:
            continue
        
        client_socket.sendall(user_input.encode('utf-8'))

        if user_input.strip().lower() == 'quit':
            print("Closting connection.")
            break
    
        response = client_socket.recv(1024).decode('utf-8')
        print(f"Response: {response}")

    client_socket.close()

if __name__ == '__main__':
    main()