// Libraries required
#include<iostream>
#include<thread>
#include<mutex>
#include<string.h>
#include<set>
#include<vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <unordered_map>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

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

// Passphrase used for creating key and iv
const std::string PASSPHRASE = "ReplaceWithStrongPassphrase!";

bool aes_encrypt(std::string &plaintext, std::string &ciphertext, unsigned char key[32], unsigned char iv[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outlen = 0;
    std::vector<unsigned char>outbuf(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if(EVP_EncryptUpdate(ctx, outbuf.data(), &outlen, reinterpret_cast<unsigned char *>(plaintext.data()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;      
    }

    int templen = 0;
    if(EVP_EncryptFinal_ex(ctx, outbuf.data() + outlen, &templen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    outlen += templen;
    ciphertext.assign(reinterpret_cast<char *>(outbuf.data()), outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_decrypt(std::string &ciphertext, std::string &plaintext, unsigned char key[32], unsigned char iv[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outlen = 0;
    std::vector<unsigned char>outbuf(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    if(EVP_DecryptUpdate(ctx, outbuf.data(), &outlen, reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int templen = 0;
    if(EVP_DecryptFinal_ex(ctx, outbuf.data() + outlen, &templen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    outlen += templen;
    plaintext.assign(reinterpret_cast<char *>(outbuf.data()), outlen);
    return true;
}

bool recv_all(int sock_fd, void *buff, int len) {
    char *ptr = (char *)buff;
    while(len > 0) {
        ssize_t s = recv(sock_fd, ptr, len, 0);
        if(s <= 0) return false;
        ptr += s;
        len -= s;
    }
    return true;
}

bool recv_message(int sock_fd, std::string &message) {
    uint32_t _4Bytes;
    if(!recv_all(sock_fd, &_4Bytes, sizeof(_4Bytes))) return false;
    uint32_t dataSize = ntohl(_4Bytes);
    if(dataSize == 0) {
        message.clear();
        return true;
    }
    message.resize(dataSize);
    if(!recv_all(sock_fd, &message[0], dataSize)) return false;
    return true;
}

void deriveKeyIv(unsigned char key[32], unsigned char iv[16]) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(PASSPHRASE.data()), PASSPHRASE.size(), hash1);   
    memcpy(key, hash1, 32); 
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    std::string iv_source = PASSPHRASE + "_iv";
    SHA256(reinterpret_cast<unsigned char *>(iv_source.data()), iv_source.size(), hash2);
    memcpy(iv, hash2, 16);
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

bool send_all(int client_fd, void *buff, int len) {
    const char *ptr = (const char *)buff;
    while(len) {
        ssize_t s = send(client_fd, ptr, len, 0);
        if(s <= 0) return false;
        len -= s;
        ptr += s;
    }
    return true;
}

void sendToClient(std::string &msg, int client_fd, unsigned char key[32], unsigned char iv[16]) {
    std::string encrypt;
    if(!aes_encrypt(msg, encrypt, key, iv)) {
        std::cerr << "Encryption failed" << std::endl;
        return;
    }
    uint32_t _4Bytes = htonl(static_cast<uint32_t>(encrypt.size()));
    if(!send_all(client_fd, &_4Bytes, sizeof(_4Bytes))) return;

    if(!send_all(client_fd, &encrypt[0], encrypt.size())) return;
}

// This function will broadcast messages to all the clients except the sender client 
void broadCast(std::string msg, int sender_fd, unsigned char key[32], unsigned char iv[16]) {
    std::lock_guard<std::mutex>lock(clientMtx);
    for(auto client : clients) {
        if(client.first != sender_fd) {
            sendToClient(msg, client.first, key, iv);
        }
    }
}

// This function will check whether the message sent by client is for particular client i.e a private message
// If it's a private message, it'll sent to that particular client and this function returns TRUE
// If it's not a private message, this function will return FALSE
bool privateMessage(std::string &msg, std::string &username, unsigned char key[32], unsigned char iv[16]) {
    if(!msg.empty() && msg[0] == '@') {
        std::istringstream iss(msg);
        std::string targetUser;
        iss >> targetUser;
        targetUser.erase(0, 1); // removing @ from the string
        if(users.find(targetUser) != users.end()) {
            std::lock_guard<std::mutex>lock(clientMtx);
            std::string privateMsg;
            std::getline(iss, privateMsg);
            privateMsg = "(" + getCurrentTime() + ")" + "(Private) [" + username + "] to [" + targetUser + "] : " + privateMsg;
            std::cout << RED << privateMsg << RESET << std::endl;
            sendToClient(privateMsg, users[targetUser], key, iv);
            return true;
        } 
    }
    return false;
}

// This function is executing on thread created for particular client
//      a. It receives the username from the client and map it the client file descriptor and vice a versa
//      b. Then it runs a inifite loop from where it receives new message coming form client 
//      c. If the message is private, then it route it to private function else broadcast to everyone
void HandleClients(int client_fd, unsigned char key[32], unsigned char iv[16]) {
    std::string encryptedUserName;
    if(!recv_message(client_fd, encryptedUserName)) {
        close(client_fd);
        return;
    }

    std::string username;
    if(!aes_decrypt(encryptedUserName, username, key, iv)) {
        close(client_fd);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(clientMtx);
        clients[client_fd] = username;
        users[username] = client_fd;
    }

    std::cout << YELLOW << "[" << getCurrentTime() << "] " << username << " joined the chat" << RESET << std::endl;
    broadCast("[" + getCurrentTime() + "] " + username + " joined the chat", client_fd, key, iv);

    while(true) {
        std::string encryptedMsg;
        if(!recv_message(client_fd, encryptedMsg)) {
            std::string timestr = getCurrentTime();
            std::cout << YELLOW << "[" << timestr << "]" << username << " left the chat" << RESET << std::endl;
            broadCast("[" + timestr + "]" + username + " left the chat", client_fd, key, iv);
            close(client_fd);
            {
                std::lock_guard<std::mutex> lock(clientMtx);
                clients.erase(client_fd);
            }
            break;
        }
        
        std::string decryptedMsg;
        aes_decrypt(encryptedMsg, decryptedMsg, key, iv);
        if(!privateMessage(decryptedMsg, username, key, iv)) {
            std::string timestr = getCurrentTime();
            std::string formatted = "[" + timestr + "]" + "[" + username + "] : " + decryptedMsg;
            broadCast(formatted, client_fd, key, iv);
            std::cout << GREEN << formatted << RESET << std::endl;
        }
    }
}

int main() {

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    unsigned char key[32], iv[16];
    deriveKeyIv(key, iv);  

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

    // This allows the socket to be reused quickly. Good for server restart
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

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

    std::cout << "🔐 Encrypted chat server started on port 8080"  << " ...\n";

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
        std::thread(HandleClients, client_fd, key, iv).detach();
    }


    return 0;
}