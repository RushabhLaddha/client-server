**A) Download the Repo :**
  Clone or Download the repository

**B) Pre-requisite Libraries :**
  sudo apt install libssl-dev

**C) Build the code :**
  g++ server.cpp -o server -pthread -lssl -lcrypto
  g++ client.cpp -o client -pthread -lssl -lcrypto

**D) Run the Server :**
  ./server

**E) Run the Clients (Multiple Clients supported):**
  ./client