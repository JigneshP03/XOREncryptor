#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <openssl/sha.h>
#include <termios.h>
#include <unistd.h>

#define CHUNK_SIZE 4096

std::mutex cout_mutex;

// Secure password input
std::string getPassword() {
    std::string password;
    termios oldt, newt;

    std::cout << "Enter password: ";
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    std::cout << "\n";
    return password;
}

// Read file securely into vector
bool readFile(const std::string& filename, std::vector<uint8_t>& buffer) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    buffer.resize(size);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return true;
}

// Write file
bool writeFile(const std::string& filename, const std::vector<uint8_t>& buffer) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}

// SHA-256 checksum
std::vector<uint8_t> calculateChecksum(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// XOR encryption in chunks
void xorChunk(std::vector<uint8_t>& data, const std::vector<uint8_t>& key, size_t start, size_t end) {
    size_t keyLen = key.size();
    for (size_t i = start; i < end; ++i) {
        data[i] ^= key[i % keyLen];
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <input> <output> <keyfile>\n";
        return 1;
    }

    std::string inputFile = argv[1];
    std::string outputFile = argv[2];
    std::string keyFile = argv[3];

    std::string password = getPassword();
    if (password.empty()) {
        std::cerr << "Password required.\n";
        return 1;
    }

    std::vector<uint8_t> inputData, keyData;
    if (!readFile(inputFile, inputData)) {
        std::cerr << "Error reading input file.\n";
        return 1;
    }

    if (!readFile(keyFile, keyData)) {
        std::cerr << "Error reading key file.\n";
        return 1;
    }

    size_t numThreads = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;
    size_t dataSize = inputData.size();
    size_t chunkSize = dataSize / numThreads;

    // Multithreaded XOR
    for (size_t i = 0; i < numThreads; ++i) {
        size_t start = i * chunkSize;
        size_t end = (i == numThreads - 1) ? dataSize : start + chunkSize;
        threads.emplace_back(xorChunk, std::ref(inputData), std::ref(keyData), start, end);
    }

    for (auto& t : threads) t.join();

    // Append checksum if encrypting
    bool isEncrypting = inputFile.find(".enc") == std::string::npos;

    if (isEncrypting) {
        std::vector<uint8_t> checksum = calculateChecksum(inputData);
        inputData.insert(inputData.end(), checksum.begin(), checksum.end());
    } else {
        // Extract checksum and verify
        if (inputData.size() < SHA256_DIGEST_LENGTH) {
            std::cerr << "Invalid encrypted file.\n";
            return 1;
        }
        std::vector<uint8_t> storedChecksum(inputData.end() - SHA256_DIGEST_LENGTH, inputData.end());
        inputData.resize(inputData.size() - SHA256_DIGEST_LENGTH);

        std::vector<uint8_t> actualChecksum = calculateChecksum(inputData);
        if (storedChecksum != actualChecksum) {
            std::cerr << "Checksum mismatch. File may be corrupted.\n";
            return 1;
        }
    }

    if (!writeFile(outputFile, inputData)) {
        std::cerr << "Error writing to output file.\n";
        return 1;
    }

    // Securely erase key
    std::fill(keyData.begin(), keyData.end(), 0);
    std::cout << "Operation successful.\n";
    return 0;
}
