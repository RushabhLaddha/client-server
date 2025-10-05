#include<iostream>
#include<sys/socket.h>
#include<arpa/inet.h> // For inet_pton()
#include<unistd.h>
#include<string.h>
#include<thread>

void receiveMsg(int client_fd) {
    char buffer[1024];
    while(true) {
        int bytesRecv = recv(client_fd, &buffer, sizeof(buffer), 0);
        if(bytesRecv <= 0) break;
        buffer[bytesRecv] = '\0';
        std::cout << buffer << std::endl;
    }
}

int main() {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(sock_fd < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return -1;
    }

    sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(8080);

    if(inet_pton(AF_INET, "127.0.0.1", &client_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/Address not supported\n";
        return -1;
    }

    if(connect(sock_fd, (const sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return -1;
    }

    std::thread(receiveMsg, sock_fd).detach();

    std::string username;
    std::cout << "Enter username : ";
    std::getline(std::cin, username);
    send(sock_fd, username.c_str(), strlen(username.c_str()), 0);

    std::string msg;
    while(true) {
        std::getline(std::cin, msg);
        if(msg == "exit") break;
        send(sock_fd, msg.c_str(), strlen(msg.c_str()), 0);
    }

    close(sock_fd);
}