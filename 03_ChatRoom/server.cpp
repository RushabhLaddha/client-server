#include<iostream>
#include<thread>
#include<mutex>
#include<string.h>
#include<set>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <unordered_map>

std::unordered_map<int, std::string>clients;
std::mutex clientMtx;

void broadCast(std::string msg, int sender_fd) {
    std::lock_guard<std::mutex>lock(clientMtx);
    for(auto client : clients) {
        if(client.first != sender_fd) {
            send(client.first, msg.c_str(), strlen(msg.c_str()), 0);
        }
    }
}

void HandleClients(int client_fd) {
    char buffer[1024] = {0};

    int user_len = recv(client_fd, &buffer, sizeof(buffer), 0);
    std::string username(buffer, user_len);

    {
        std::lock_guard<std::mutex> lock(clientMtx);
        clients[client_fd] = username;
    }

    std::cout << username << " joined the chat" << std::endl;
    broadCast(username + " joined the chat", client_fd);

    while(true) {
        int bytesRecv = recv(client_fd, &buffer, sizeof(buffer), 0);

        if(bytesRecv <= 0) {
            std::cout << username << " left the chat" << std::endl;
            broadCast(username + " left the chat", client_fd);
            close(client_fd);
            {
                std::lock_guard<std::mutex> lock(clientMtx);
                clients.erase(client_fd);
            }
            break;
        }

        std::string msg(buffer, bytesRecv);
        std::string formatted = "[" + username + "] : " + msg;
        std::cout << formatted << std::endl;
        broadCast(formatted, client_fd);
    }
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return -1;
    }

    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if(bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Binding failed" << std::endl;
        return -1;
    }

    if(listen(server_fd, 5) < 0) {
        std::cerr << "Listening failed" << std::endl;
        return -1;
    }

    while(true) {
        sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

        if(client_fd < 0) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }
        std::thread(HandleClients, client_fd).detach();
    }


    return 0;
}