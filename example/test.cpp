#include <fstream>
#include <iostream>
#include <array>
#include <bit>
#include <cstdint>
#include <cassert>
#include <limits>

template <std::integral T>
static void WriteLE(std::ofstream& file, T const& x) {
  if constexpr (std::endian::native == std::endian::little) {
    auto memory = reinterpret_cast<char const*>(&x);
    file.write(memory, sizeof(T));
  } else {
    static_assert(std::endian::native == std::endian::big);
    auto memory_be = reinterpret_cast<char const*>(&x);
    std::array<char, sizeof(T)> memory_le;
    for (size_t i = 0; i < sizeof(T); i++) {
      memory_le[sizeof(T) - i - 1] = memory_be[i];
    }
    file.write(memory_le.begin(), memory_le.size());
  }
}

template <std::integral T>
static bool ReadLE(std::ifstream& file, T* out) {
  char* base = reinterpret_cast<char*>(out);
  if constexpr (std::endian::native == std::endian::little) {
    file.read(base, sizeof(T));
    if (file.gcount() < sizeof(T)) return false;
  } else {
    static_assert(std::endian::native == std::endian::big);
    std::array<char, sizeof(T)> memory_le;
    file.read(&memory_le[0], sizeof(T));
    if (file.gcount() < sizeof(T)) return false;
    for (size_t i = 0; i < sizeof(T); i++) {
      base[sizeof(T) - i - 1] = memory_le[i];
    }
  }
  return true;
}

struct ConfigData {
    uint64_t version;
    int32_t temperature;
    uint16_t humidity;
};

void WriteConfigData(std::ofstream& file, const ConfigData& data) {
    WriteLE(file, data.version);
    WriteLE(file, data.temperature);
    WriteLE(file, data.humidity);
}

bool ReadConfigData(std::ifstream& file, ConfigData* data) {
    if (!ReadLE(file, &data->version)) return false;
    if (!ReadLE(file, &data->temperature)) return false;
    if (!ReadLE(file, &data->humidity)) return false;
    return true;
}

int main() {
    ConfigData dataToWrite = {
        std::numeric_limits<uint64_t>::max(),
        std::numeric_limits<int32_t>::min(),
        std::numeric_limits<uint16_t>::max(),
    };
    ConfigData dataToRead;

    std::ofstream outputFile("config.bin", std::ios::binary);
    WriteConfigData(outputFile, dataToWrite);
    outputFile.close();

    std::ifstream inputFile("config.bin", std::ios::binary);
    if (ReadConfigData(inputFile, &dataToRead)) {
        std::cout << "Version: " << dataToRead.version << std::endl;
        std::cout << "Temperature: " << dataToRead.temperature << std::endl;
        std::cout << "Humidity: " << dataToRead.humidity << std::endl;
    } else {
        std::cerr << "Failed to read config data." << std::endl;
    }
    inputFile.close();

    return 0;
}
