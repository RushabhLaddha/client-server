#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

int main() {
    // 1. Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        std::cerr << "Socket creation failed\n";
        return -1;
    }

    // 2. Define server address (IP + Port)
    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr.s_addr); 
    address.sin_port = htons(8080);

    // 3. Bind socket to the address
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed\n";
        return -1;
    }

    // 4. Start listening for clients
    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed\n";
        return -1;
    }
    std::cout << "Server is listening on port 8080...\n";

    // 5. Accept a client connection
    int addrlen = sizeof(address);
    int new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        std::cerr << "Accept failed\n";
        return -1;
    }

    int count = 2;
    while(count--) {
        char buffer[1024] = {0};
        read(new_socket, buffer, 1024);
        std::cout << "Rushabh >> " << buffer << "\n";
        std::cout << "You     >> ";

        std::string reply;
        std::getline(std::cin, reply);
        send(new_socket, reply.c_str(), strlen(reply.c_str()), 0);
    }

    // 8. Close sockets
    close(new_socket);
    close(server_fd);

    return 0;
}
