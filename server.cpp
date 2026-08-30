#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

struct ClientSession {
    int socket_fd;
    string key;
};

unordered_map<string, ClientSession> client_table;
mutex table_mutex;

string xor_cipher(const string& text, const string& key) {
    if (key.empty()) return text;
    string output = text;
    for (size_t i = 0; i < text.size(); ++i) {
        output[i] = text[i] ^ key[i % key.size()];
    }
    return output;
}

void send_raw(int sock, const string& msg) {
    send(sock, msg.c_str(), msg.size(), 0);
}

void handle_client(int client_sock) {
    char buffer[4096];
    string username = "";
    string user_key = "";

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) break;

        string incoming(buffer, bytes_read);

        // Client registration is sent unencrypted during initial handshake
        if (incoming.rfind("REGISTER", 0) == 0) {
            stringstream ss(incoming);
            string cmd, temp_user, key_kw, temp_key;
            ss >> cmd >> temp_user >> key_kw >> temp_key;

            if (temp_user.empty() || key_kw != "KEY" || temp_key.empty()) {
                send_raw(client_sock, "ERROR invalid command format\n");
                continue;
            }

            lock_guard<mutex> lock(table_mutex);
            if (client_table.find(temp_user) != client_table.end()) {
                send_raw(client_sock, "ERROR username " + temp_user + " already taken\n");
            } else {
                username = temp_user;
                user_key = temp_key;
                client_table[username] = {client_sock, user_key};
                send_raw(client_sock, "REGISTERED " + username + "\n");
            }
            continue;
        }

        if (user_key.empty()) {
            send_raw(client_sock, "ERROR not registered\n");
            continue;
        }

        // Decrypt incoming payload with sender key
        string decrypted = xor_cipher(incoming, user_key);

        if (decrypted.rfind("QUIT", 0) == 0) {
            string resp = "GOODBYE " + username + "\n";
            send_raw(client_sock, xor_cipher(resp, user_key));
            break;
        } 
        else if (decrypted.rfind("LIST", 0) == 0) {
            lock_guard<mutex> lock(table_mutex);
            string resp = "ONLINE ";
            bool first = true;
            for (const auto& [name, session] : client_table) {
                if (!first) resp += ", ";
                resp += name;
                first = false;
            }
            resp += "\n";
            send_raw(client_sock, xor_cipher(resp, user_key));
        } 
        else if (decrypted.rfind("SEND TO", 0) == 0) {
            size_t colon_pos = decrypted.find(':');
            if (colon_pos == string::npos) {
                string err = "ERROR invalid command format\n";
                send_raw(client_sock, xor_cipher(err, user_key));
                continue;
            }

            string header = decrypted.substr(0, colon_pos);
            string message = decrypted.substr(colon_pos + 1);
            if (!message.empty() && message.front() == ' ') message.erase(0, 1);

            stringstream ss(header);
            string cmd1, cmd2, target_user;
            ss >> cmd1 >> cmd2 >> target_user;

            lock_guard<mutex> lock(table_mutex);
            if (client_table.find(target_user) == client_table.end()) {
                string err = "ERROR " + target_user + " is not online\n";
                send_raw(client_sock, xor_cipher(err, user_key));
            } else {
                string forward_msg = "FROM " + username + ": " + message;
                string target_key = client_table[target_user].key;
                int target_sock = client_table[target_user].socket_fd;
                send_raw(target_sock, xor_cipher(forward_msg, target_key));
            }
        } 
        else if (decrypted.rfind("SENDFILE TO", 0) == 0) {
            size_t newline_pos = decrypted.find('\n');
            if (newline_pos == string::npos) {
                string err = "ERROR invalid command format\n";
                send_raw(client_sock, xor_cipher(err, user_key));
                continue;
            }

            string header = decrypted.substr(0, newline_pos);
            string file_content = decrypted.substr(newline_pos + 1);

            stringstream ss(header);
            string cmd1, cmd2, target_user, filename;
            size_t file_size;
            ss >> cmd1 >> cmd2 >> target_user >> filename >> file_size;

            lock_guard<mutex> lock(table_mutex);
            if (client_table.find(target_user) == client_table.end()) {
                string err = "ERROR " + target_user + " is not online\n";
                send_raw(client_sock, xor_cipher(err, user_key));
            } else {
                string forward_header = "RECVFILE FROM " + username + " " + filename + " " + to_string(file_size) + "\n";
                string full_forward = forward_header + file_content;
                string target_key = client_table[target_user].key;
                int target_sock = client_table[target_user].socket_fd;
                send_raw(target_sock, xor_cipher(full_forward, target_key));
            }
        } 
        else {
            string err = "ERROR unknown command\n";
            send_raw(client_sock, xor_cipher(err, user_key));
        }
    }

    if (!username.empty()) {
        lock_guard<mutex> lock(table_mutex);
        client_table.erase(username);
    }
    close(client_sock);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(stoi(argv[1]));
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 10);

    cout << "Server active on port " << argv[1] << "...\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock >= 0) {
            thread(handle_client, client_sock).detach();
        }
    }

    close(server_sock);
    return 0;
}