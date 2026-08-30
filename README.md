# Team Secure Chat Application
## Group Members
Anurag Anand (2405417) - server, client, cipher, testing

## How to Build
g++ -pthread server.cpp -o server
g++ -pthread client.cpp -o client

## How to Run
Server: ./server <port>
Client: ./client <server_ip> <port>

## Cipher Choice
We chose Repeating-Key XOR because [insert reasoning].
Known weakness: [insert explanation, e.g., vulnerable to frequency analysis if the key is short].

## Design Notes
* Hop-by-hop (not end-to-end) encryption: server decrypts and re-encrypts per client key.
* File transfer size cap: 1 MB.
* Concurrency model: std::thread chosen because [insert reasoning].

## Known Limitations
[List any bugs, missing features, or unhandled edge cases here]