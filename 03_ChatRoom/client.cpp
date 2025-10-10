// Libraries required
#include<iostream>
#include<sys/socket.h>
#include<arpa/inet.h> // For inet_pton()
#include<unistd.h>
#include<string.h>
#include<thread>
#include<vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

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
        std::cout<<"a\n";
        return false;
    }

    int outlen = 0;
    std::vector<unsigned char>outbuf(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    if(EVP_DecryptUpdate(ctx, outbuf.data(), &outlen, reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size()) != 1) {
        std::cout<<"b\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int templen = 0;
    if(EVP_DecryptFinal_ex(ctx, outbuf.data() + outlen, &templen) != 1) {
        std::cout<<"c\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    outlen += templen;
    plaintext.assign(reinterpret_cast<char *>(outbuf.data()), outlen);
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

void sendToServer(std::string &msg, int client_fd, unsigned char key[32], unsigned char iv[16]) {
    std::string encrypt;
    if(!aes_encrypt(msg, encrypt, key, iv)) {
        std::cerr << "Encryption failed" << std::endl;
        return;
    }
    uint32_t _4Bytes = htonl(static_cast<uint32_t>(encrypt.size()));
    if(!send_all(client_fd, &_4Bytes, sizeof(_4Bytes))) return;

    if(!send_all(client_fd, &encrypt[0], encrypt.size())) return;
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

// This function runs on a independent thread to receive message from Server
void receiveMsg(int client_fd, unsigned char key[32], unsigned char iv[16]) {
    while(true) {
        uint32_t _4Bytes;
        if(!recv_all(client_fd, &_4Bytes, sizeof(_4Bytes))) break;
        uint32_t dataSize = ntohl(_4Bytes);
        if(dataSize == 0) break;
        std::string encryptedMsg(dataSize, 0);
        if(!recv_all(client_fd, &encryptedMsg[0], dataSize)) break;
        std::string msg;
        if(!aes_decrypt(encryptedMsg, msg, key, iv)) {
            std::cerr << "Failed to decrypt message" <<std::endl;
            continue;
        }
        std::cout << msg <<std::endl;
    }
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    unsigned char key[32], iv[16];
    deriveKeyIv(key, iv);
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(sock_fd < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return -1;
    }

    sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(8080);

    // Convert human readable IP Address into Binary network format and store it in the structure
    if(inet_pton(AF_INET, "127.0.0.1", &client_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/Address not supported\n";
        return -1;
    }

    // Sends connection request to the Server
    if(connect(sock_fd, (const sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return -1;
    }

    // Takes username from the client with which it should be identified on the Server and send it to the server
    std::string username;
    std::cout << "Enter username : ";
    std::getline(std::cin, username);
    sendToServer(username, sock_fd, key, iv);

    // Creates a new thread for receiving message from Server
    std::thread(receiveMsg, sock_fd, key, iv).detach();

    // Client send messages to the server
    std::string msg;
    while(true) {
        std::getline(std::cin, msg);
        if(msg == "exit") break;
        sendToServer(msg, sock_fd, key, iv);
    }

    // Close the socket
    close(sock_fd);
}