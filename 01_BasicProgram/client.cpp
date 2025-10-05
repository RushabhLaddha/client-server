#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>   // For inet_pton()
#include <unistd.h>
#include <string.h>

int main() {
    // 1. Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation error\n";
        return -1;
    }

    // 2. Define server address
    sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);

    // 3. Convert IP string to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/Address not supported\n";
        return -1;
    }

    // 4. Connect to server
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed\n";
        return -1;
    }

    // 5. Send message to server
    const char* msg = "Hello Server";
    send(sock, msg, strlen(msg), 0);

    // 6. Receive server reply
    char buffer[1024] = {0};
    read(sock, buffer, 1024);
    std::cout << "Server says: " << buffer << "\n";

    // 7. Close socket
    close(sock);

    return 0;
}
