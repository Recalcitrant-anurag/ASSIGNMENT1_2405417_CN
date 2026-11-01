#include <iostream>
using namespace std;
int main() {
    auto lang = "C++";
    cout << "Hello and welcome to " << lang << "!\n";
    for (int i = 1; i <= 5; i++) {
        cout << "i = " << i << std::endl;
    }
    return 0;
}