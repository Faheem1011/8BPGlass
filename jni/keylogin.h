#include <json/json.hpp>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <random>

#include "include/obfuscate.h"

bool bValid = false;

std::string xor_encrypt(const std::string& data, const std::string& key) {
    std::string result;
    result.reserve(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result += data[i] ^ key[i % key.length()];
    }
    return result;
}

std::string xor_decrypt(const std::string& data, const std::string& key) {
    return xor_encrypt(data, key);
}

std::string base64_encode(const std::string& data) {
    static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    size_t i = 0;
    unsigned char a3[3];
    unsigned char a4[4];

    while (data.length() - i >= 3) {
        a3[0] = static_cast<unsigned char>(data[i]);
        a3[1] = static_cast<unsigned char>(data[i + 1]);
        a3[2] = static_cast<unsigned char>(data[i + 2]);

        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
        a4[3] = a3[2] & 0x3f;

        for (int j = 0; j < 4; j++)
            result += chars[a4[j]];

        i += 3;
    }

    if (data.length() - i > 0) {
        int remaining = data.length() - i;
        for (int j = 0; j < 3; j++)
            a3[j] = (j < remaining) ? static_cast<unsigned char>(data[i + j]) : 0;

        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
        a4[3] = a3[2] & 0x3f;

        for (int j = 0; j < remaining + 1; j++)
            result += chars[a4[j]];
        while (result.length() % 4)
            result += '=';
    }

    return result;
}

std::string base64_decode(const std::string& input) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T[static_cast<unsigned char>(chars[i])] = i;

    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            result.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return result;
}

INLINE std::string getDt(int offsetSeconds = 0) {
    using namespace std::chrono;
    system_clock::time_point now = system_clock::now();
    system_clock::time_point ist = now + hours(3) + seconds(offsetSeconds);
    std::time_t t = system_clock::to_time_t(ist);

    std::tm tm{};
    gmtime_r(&t, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

INLINE std::string gToken(const std::string& data, const std::string& key) {
    std::string encrypted = xor_encrypt(data, key);
    std::string encoded = base64_encode(encrypted);
    return encoded;
}

INLINE std::string decryptData(const std::string& encryptedData, const std::string& key) {
    try {
        auto jsonObj = nlohmann::json::parse(encryptedData);

        if (!jsonObj.contains("data") || !jsonObj["data"].is_string())
            return "";

        std::string encoded = jsonObj["data"].get<std::string>();
        std::string decoded = base64_decode(encoded);
        return xor_decrypt(decoded, key);
    } catch (...) {
        return "";
    }
}

struct WebSocketFrame {
    std::string data;
    bool success;
};

inline std::string generateWebSocketKey() {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string key;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 63);
    for (int i = 0; i < 16; i++) {
        key += charset[dis(gen)];
    }
    return base64_encode(key);
}

inline std::string createWebSocketFrame(const std::string& message) {
    std::string frame;
    frame += (char)0x81;
    
    size_t len = message.length();
    if (len <= 125) {
        frame += (char)(0x80 | len);
    } else if (len <= 65535) {
        frame += (char)(0x80 | 126);
        frame += (char)((len >> 8) & 0xFF);
        frame += (char)(len & 0xFF);
    } else {
        frame += (char)(0x80 | 127);
        for (int i = 7; i >= 0; i--) {
            frame += (char)((len >> (i * 8)) & 0xFF);
        }
    }
    
    unsigned char mask[4];
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < 4; i++) {
        mask[i] = dis(gen);
        frame += mask[i];
    }
    
    for (size_t i = 0; i < message.length(); i++) {
        frame += message[i] ^ mask[i % 4];
    }
    
    return frame;
}

inline WebSocketFrame parseWebSocketFrame(const char* data, size_t dataLen) {
    WebSocketFrame result;
    result.success = false;
    
    if (dataLen < 2) return result;
    
    size_t payloadLen = data[1] & 0x7F;
    size_t headerLen = 2;
    
    if (payloadLen == 126) {
        if (dataLen < 4) return result;
        payloadLen = ((unsigned char)data[2] << 8) | (unsigned char)data[3];
        headerLen = 4;
    } else if (payloadLen == 127) {
        if (dataLen < 10) return result;
        payloadLen = 0;
        for (int i = 0; i < 8; i++) {
            payloadLen = (payloadLen << 8) | (unsigned char)data[2 + i];
        }
        headerLen = 10;
    }
    
    if (dataLen < headerLen + payloadLen) return result;
    
    result.data = std::string(data + headerLen, payloadLen);
    result.success = true;
    return result;
}

inline int connectWebSocket(const char* host, int port, int timeoutSec = 10) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct timeval timeout;
    timeout.tv_sec = timeoutSec;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &serverAddr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(sock);
        return -1;
    }
    
    std::string wsKey = generateWebSocketKey();
    std::stringstream request;
    request << "GET / HTTP/1.1\r\n";
    request << "Host: " << host << ":" << port << "\r\n";
    request << "Upgrade: websocket\r\n";
    request << "Connection: Upgrade\r\n";
    request << "Sec-WebSocket-Key: " << wsKey << "\r\n";
    request << "Sec-WebSocket-Version: 13\r\n";
    request << "\r\n";
    
    std::string reqStr = request.str();
    if (send(sock, reqStr.c_str(), reqStr.length(), 0) < 0) {
        close(sock);
        return -1;
    }
    
    char buffer[1024];
    ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        close(sock);
        return -1;
    }
    buffer[received] = '\0';
    
    if (strstr(buffer, "101") == nullptr) {
        close(sock);
        return -1;
    }
    
    return sock;
}

inline std::string sendWebSocketMessage(int sock, const std::string& message, int timeoutSec = 10) {
    std::string frame = createWebSocketFrame(message);
    if (send(sock, frame.c_str(), frame.length(), 0) < 0) {
        return "";
    }
    
    char buffer[65536];
    ssize_t received = recv(sock, buffer, sizeof(buffer), 0);
    if (received <= 0) {
        return "";
    }
    
    WebSocketFrame wsFrame = parseWebSocketFrame(buffer, received);
    if (!wsFrame.success) {
        return "";
    }
    
    return wsFrame.data;
}

std::string ERROR_MESSAGE = "";

static bool logged_in = false;
static bool is_logging_in = false;
std::string g_Token, g_Auth;
std::string g_ExpTime = "N/A";

INLINE bool Login(std::string androidID, std::string key) {
    bValid = true;
    logged_in = true;
    is_logging_in = false;
    g_Token = OO("bypass").str();
    g_Auth = OO("bypass").str();
    g_ExpTime = OO("Never").str();
    persistent_string["key"] = key;
    return true;
}
