# Team Secure Chat Application

## Group Members

Anurag Anand (2405417) - server, client, cipher, testing

## How to Build

g++ -pthread server.cpp -o server
g++ -pthread client.cpp -o client

## How to Run

Server: ./server <port></port>
Client: ./client <server_ip> <port></port>

## Cipher Choice

We chose Repeating-Key XOR because it is lightweight, uses native C++ bitwise operations, and easily encrypts all ASCII characters—including our protocol's spaces and newlines—without requiring complex logic or external libraries

**Known weakness:**
It is highly vulnerable to known-plaintext attacks. Because our chat protocol uses predictable text headers (like "SEND TO"), an attacker intercepting the traffic can easily use those known words to reveal the repeating key and crack the cipher

## Design Notes

* Hop-by-hop (not end-to-end) encryption: server decrypts and re-encrypts per client key.
* File transfer size cap: 1 MB.
<<<<<<< HEAD
* **Concurrency model:** thread chosen because it is built directly into modern C++, making it straightforward to implement without needing complex event loops like select or epoll. It perfectly handles our blocking I/O operations (like waiting to receive a message) by allowing each client connection to run independently in the background without freezing the main server loop
=======
* Concurrency model: std::thread chosen because [insert reasoning].
>>>>>>> 12d66e413faba2b4a7fa75455aa2e7a6ad94d723
