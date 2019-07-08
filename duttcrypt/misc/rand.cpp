#include <iostream>
#include <random>

int main() {
    std::mt19937 mt(1);
    std::uniform_int_distribution<unsigned int> dis;
    for(int i = 0; i < 2500; ++i) {
        std::cout << dis(mt) << std::endl;
    }
    return 0;
}
