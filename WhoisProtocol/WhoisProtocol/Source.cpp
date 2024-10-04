#include <iostream>
#include <string>
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "43"
#define WHOIS_SERVER "whois.iana.org"
#define LOCAL "localhost"

int main() {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;
    char sendbuf[DEFAULT_BUFLEN];
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo(WHOIS_SERVER, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cout << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        return 1;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            std::cout << "Error at socket(): " << WSAGetLastError() << std::endl;
            freeaddrinfo(result);
            WSACleanup();
            return 1;
        }

        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        std::cout << "Unable to connect to server!" << std::endl;
        WSACleanup();
        return 1;
    }

    std::string query = "google.com\r\n";
    iResult = send(ConnectSocket, query.c_str(), query.length(), 0);
    if (iResult == SOCKET_ERROR) {
        std::cout << "send failed: " << WSAGetLastError() << std::endl;
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }


    do {
        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0)
            std::cout << std::string(recvbuf, recvbuf + iResult);
        else if (iResult == 0)
            std::cout << "Connection closed" << std::endl;
        else
            std::cout << "recv failed: " << WSAGetLastError() << std::endl;
    } while (iResult > 0);

    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}