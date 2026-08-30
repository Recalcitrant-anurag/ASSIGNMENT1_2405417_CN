#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

string active_key = "";
bool is_registered = false;
bool running = true;

string xor_cipher(const string& text, const string& key) {
    if (key.empty()) return text;
    string output = text;
    for (size_t i = 0; i < text.size(); ++i) {
        output[i] = text[i] ^ key[i % key.size()];
    }
    return output;
}

string extract_filename(const string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == string::npos) return path;
    return path.substr(pos + 1);
}

void receiver_loop(int sock) {
    char buffer[4096];
    while (running) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) {
            if (running) cout << "\n[Server disconnected]\n";
            exit(0);
        }

        string raw_data(buffer, bytes_read);

        if (!is_registered) {
            cout << raw_data;
            if (raw_data.rfind("REGISTERED", 0) == 0) {
                is_registered = true;
            }
            continue;
        }

        string decrypted = xor_cipher(raw_data, active_key);

        if (decrypted.rfind("RECVFILE FROM", 0) == 0) {
            size_t newline_pos = decrypted.find('\n');
            string header = decrypted.substr(0, newline_pos);
            string content = decrypted.substr(newline_pos + 1);

            stringstream ss(header);
            string tag, from_kw, sender, filename;
            size_t filesize;
            ss >> tag >> from_kw >> sender >> filename >> filesize;

            string out_path = "received_" + filename;
            ofstream out_file(out_path, ios::binary);
            if (out_file.is_open()) {
                out_file.write(content.c_str(), filesize);
                out_file.close();
                cout << sender << "$ RECVFILE FROM " << sender << ": " << filename << " (" << filesize << " bytes)\n";
                cout << "[content saved to ./" << out_path << "]\n";
            }
        } else {
            cout << decrypted;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(stoi(argv[2]));
    inet_pton(AF_INET, argv[1], &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Connection failed.\n";
        return 1;
    }

    thread(receiver_loop, sock).detach();

    string line;
    while (getline(cin, line)) {
        if (line.empty()) continue;

        if (line.rfind("REGISTER", 0) == 0) {
            stringstream ss(line);
            string cmd, uname, key_kw, parsed_key;
            ss >> cmd >> uname >> key_kw >> parsed_key;
            active_key = parsed_key;
            send(sock, line.c_str(), line.size(), 0);
        } 
        else if (line.rfind("SENDFILE TO", 0) == 0) {
            size_t colon_pos = line.find(':');
            if (colon_pos == string::npos) {
                cout << "server$ ERROR invalid command format\n";
                continue;
            }

            string header_part = line.substr(0, colon_pos);
            string filepath = line.substr(colon_pos + 1);
            if (!filepath.empty() && filepath.front() == ' ') filepath.erase(0, 1);

            if (filepath.size() < 4 || filepath.substr(filepath.size() - 4) != ".txt") {
                cout << "server$ ERROR only .txt files are supported\n";
                continue;
            }

            ifstream file(filepath, ios::binary | ios::ate);
            if (!file.is_open()) {
                cout << "server$ ERROR file not found: " << filepath << "\n";
                continue;
            }

            streamsize size = file.tellg();
            if (size > 1048576) {
                cout << "server$ ERROR file exceeds 1MB limit\n";
                file.close();
                continue;
            }

            file.seekg(0, ios::beg);
            string content(size, '\0');
            file.read(&content[0], size);
            file.close();

            stringstream ss(header_part);
            string cmd1, cmd2, target_user;
            ss >> cmd1 >> cmd2 >> target_user;

            string filename = extract_filename(filepath);
            string framed_payload = "SENDFILE TO " + target_user + " " + filename + " " + to_string(size) + "\n" + content;
            string encrypted = xor_cipher(framed_payload, active_key);
            send(sock, encrypted.c_str(), encrypted.size(), 0);
        } 
        else if (line.rfind("QUIT", 0) == 0) {
            string encrypted = xor_cipher(line, active_key);
            send(sock, encrypted.c_str(), encrypted.size(), 0);
            running = false;
            break;
        } 
        else {
            string encrypted = xor_cipher(line, active_key);
            send(sock, encrypted.c_str(), encrypted.size(), 0);
        }
    }

    close(sock);
    return 0;
}