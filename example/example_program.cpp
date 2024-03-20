#include <chrono>
#include <iostream>

int main() {
  const auto now = std::chrono::system_clock::now();
  std::cout << "Current time is: " << now << std::endl;
  return 0;
}