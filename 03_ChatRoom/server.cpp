// Libraries required
#include<iostream>
#include<thread>
#include<mutex>
#include<string.h>
#include<set>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <unordered_map>
#include <sstream>
#include <ctime>
#include <iomanip>

// Color Coding Macros
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define RESET   "\x1b[0m"
#define YELLOW  "\033[33m"

// Global variables

// <client_fd, username>
std::unordered_map<int, std::string>clients;

// <username, client_fd>
std::unordered_map<std::string, int>users;

// mutex for variables shared between threads
std::mutex clientMtx;

// key used for encrypting and decrypting
const std::string key{"MyKey"};

// This function will encrypt the message to be sent over the socket
// And also decrypt the message once received
std::string xorEncryptDecrypt(std::string &msg) {
    std::string result(msg.size(), 0);
    for(int i = 0; i < msg.size(); i++) {
        result[i] = msg[i] ^ key[i % key.size()];
    }
    return result;
}

// This function will return the current time in string format 
std::string getCurrentTime() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t now_time = system_clock::to_time_t(now);

    std::tm local_tm{};
    localtime_r(&now_time, &local_tm); 

    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%I:%M %p"); 
    return oss.str();
}

// This function will broadcast messages to all the clients except the sender client 
void broadCast(std::string msg, int sender_fd) {
    std::lock_guard<std::mutex>lock(clientMtx);
    for(auto client : clients) {
        if(client.first != sender_fd) {
            std::string encrypt = xorEncryptDecrypt(msg);
            send(client.first, encrypt.c_str(), encrypt.size(), 0);
        }
    }
}

// This function will check whether the message sent by client is for particular client i.e a private message
// If it's a private message, it'll sent to that particular client and this function returns TRUE
// If it's not a private message, this function will return FALSE
bool privateMessage(std::string &msg, std::string &username, std::string &timestr) {
    if(!msg.empty() && msg[0] == '@') {
        std::istringstream iss(msg);
        std::string targetUser;
        iss >> targetUser;
        targetUser.erase(0, 1); // removing @ from the string
        if(users.find(targetUser) != users.end()) {
            std::lock_guard<std::mutex>lock(clientMtx);
            std::string privateMsg;
            std::getline(iss, privateMsg);
            privateMsg = "(" + timestr + ")" + "(Private) [" + username + "] to [" + targetUser + "] : " + privateMsg;
            std::cout << RED << privateMsg << RESET << std::endl;
            std::string encrypt = xorEncryptDecrypt(msg);
            send(users[targetUser], encrypt.c_str(), encrypt.size(), 0);
            return true;
        } 
    }
    return false;
}

// This function is executing on thread created for particular client
//      a. It receives the username from the client and map it the client file descriptor and vice a versa
//      b. Then it runs a inifite loop from where it receives new message coming form client 
//      c. If the message is private, then it route it to private function else broadcast to everyone
void HandleClients(int client_fd) {
    char buffer[1024] = {0};

    int user_len = recv(client_fd, &buffer, sizeof(buffer), 0);
    std::string encryptedUsername(buffer, user_len);
    std::string username{xorEncryptDecrypt(encryptedUsername)};

    {
        std::lock_guard<std::mutex> lock(clientMtx);
        clients[client_fd] = username;
        users[username] = client_fd;
    }

    std::cout << YELLOW << "[" << getCurrentTime() << "] " << username << " joined the chat" << RESET << std::endl;
    broadCast("[" + getCurrentTime() + "] " + username + " joined the chat", client_fd);

    while(true) {
        int bytesRecv = recv(client_fd, &buffer, sizeof(buffer), 0);
        std::string timestr = getCurrentTime();
        if(bytesRecv <= 0) {
            std::cout << YELLOW << "[" << timestr << "]" << username << " left the chat" << RESET << std::endl;
            broadCast("[" + timestr + "]" + username + " left the chat", client_fd);
            close(client_fd);
            {
                std::lock_guard<std::mutex> lock(clientMtx);
                clients.erase(client_fd);
            }
            break;
        }

        std::string encryptedMsg(buffer, bytesRecv);
        std::string msg{xorEncryptDecrypt(encryptedMsg)};
        std::string formatted = "[" + timestr + "]" + "[" + username + "] : " + msg;
        if(!privateMessage(msg, username, timestr)) {
            broadCast(formatted, client_fd);
            std::cout << GREEN << formatted << RESET << std::endl;
        }
    }
}

int main() {

    // 1. Create a socket for server
    //      a. server_fd is a file descriptor. In Linux, every stream is treated as file in which we perform input output operations
    //      b. AF_INET : IPv4
    //      c. SOCK_STREAM : Reliable sequenced connection byte stream 
    //      d. BY giving zero, we're letting the compiler decide the protocol either TCP/UDP
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return -1;
    }

    // 2. Structure to hold IP Address and port
    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    // 3. Binding the socket and port
    if(bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Binding failed" << std::endl;
        return -1;
    }

    // 4. Moving the socket/port into passive mode
    if(listen(server_fd, 5) < 0) {
        std::cerr << "Listening failed" << std::endl;
        return -1;
    }

    // 5. Waiting for the clients to connect
    //      a. Once a client is connected, a new socket is created to purely handle that client with server
    //      b. Then a thread is created and detached to receive from client and process independently
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