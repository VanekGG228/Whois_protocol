#include <iostream>
#include <vector>
#include <string>
#include "tinyxml2.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <sstream>

#pragma comment(lib, "Ws2_32.lib")

using namespace tinyxml2;

#define DEFAULT_PORT "43"



std::string GetWhoisInfo(const std::string& whoisServer, const std::string& domainName) {
    if (whoisServer.empty() || domainName.empty())
        return "Invalid data for WHOIS request.";

    int ConnectSocket;
    struct addrinfo* result = NULL, * ptr = NULL, hints; 
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(43);
    inet_pton(AF_INET, whoisServer.c_str(), &serverAddr.sin_addr);

    ZeroMemory(&hints, sizeof(hints)); 
    hints.ai_family = AF_UNSPEC; 
    hints.ai_socktype = SOCK_STREAM; 
    hints.ai_protocol = IPPROTO_TCP; 

    int iResult = getaddrinfo(whoisServer.c_str(), DEFAULT_PORT, &hints, &result);
    if (iResult != 0) { 
        std::cout << "getaddrinfo failed: " << iResult << std::endl; 
        WSACleanup(); 
        return "";
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) { 
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol); 
        if (ConnectSocket == INVALID_SOCKET) { 
            std::cout << "Error at socket(): " << WSAGetLastError() << std::endl;
            freeaddrinfo(result);
            WSACleanup();
            return "";
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

    std::string query = domainName + "\r\n";
    if (send(ConnectSocket, query.c_str(), query.length(), 0) == -1)
        std::cout << "Error sending query to WHOIS server.";

    std::stringstream response;
    char buffer[1024];
    int bytesRead;
    while ((bytesRead = recv(ConnectSocket, buffer, sizeof(buffer), 0)) > 0)
        response.write(buffer, bytesRead);

    closesocket(ConnectSocket);

    if (bytesRead == -1)
        std::cout << "Error reading response from WHOIS server.";

    return response.str();
}

void find(tinyxml2::XMLElement* node, const std::string& domainZone, std::vector<std::string>& result) {
    for (auto child = node->FirstChildElement(); child != nullptr; child = child->NextSiblingElement()) {

        if (std::string(child->Name()) == "domain") {

            if (child->Attribute("name") && std::string(child->Attribute("name")).compare(domainZone) == 0) {

                for (auto whoisServer = child->FirstChildElement("whoisServer"); whoisServer != nullptr; whoisServer = whoisServer->NextSiblingElement("whoisServer")) {
                    
                    if (auto host = whoisServer->Attribute("host")) {
                        std::string hostValue = host;
                        if (!hostValue.empty() && std::find(result.begin(), result.end(), hostValue) == result.end())
                            result.push_back(hostValue); 
                    }
                }

            }
            find(child, domainZone, result);
        }
    }
}

std::vector<std::string> GetWhoisServers(const std::string& domainZone) {

    tinyxml2::XMLDocument _serverList; 
    std::vector<std::string> result; 

    if (_serverList.LoadFile("whois-server-list.xml") != tinyxml2::XML_SUCCESS) {
        std::cerr << "Failed to load XML file!" << std::endl;
        return result;
    }

    find(_serverList.FirstChildElement("domainList"), domainZone,result);

    return result;
}

void parse(std::string s,std::vector<std::string>& levels) {
    std::stringstream ss(s);
    std::string tmp;
    std::vector<std::string> result;
    levels.push_back(s);
    for(int i = 0;i<s.length();++i) {

        if (s[i] == '.') {
            levels.push_back(s.substr(i+1, s .length()));
        } 

    }
    for (auto elem : levels) {
        std::cout << elem << std::endl;
    }
}

std::string get(std::string URL) {
    std::vector<std::string> whoisServers;
    std::vector<std::string> domainLevels;
    parse(URL, domainLevels);
    for (int i = 0; i < domainLevels.size(); ++i) {

        whoisServers = GetWhoisServers(domainLevels[i]);
        if (whoisServers.size() > 0) break;
    }

    if (whoisServers.size() == 0)
       std::cout<< "\r\n----------------\r\nUnknown domain zone";
    else {

        for (auto elem : whoisServers) {
           return GetWhoisInfo(elem, URL);
        }
    }


}




int main() {
   
    WSADATA wsaData;
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    int iResult;
    while (1) {
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            std::cout << "WSAStartup failed: " << iResult << std::endl;
            return 1;
        }

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;

        iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
        if (iResult != 0) {
            std::cout << "getaddrinfo failed: " << iResult << std::endl;
            WSACleanup();
            return 1;
        }

        ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (ListenSocket == INVALID_SOCKET) {
            std::cout << "Error at socket(): " << WSAGetLastError() << std::endl;
            freeaddrinfo(result);
            WSACleanup();
            return 1;
        }

        iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            std::cout << "bind failed: " << WSAGetLastError() << std::endl;
            freeaddrinfo(result);
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }

        freeaddrinfo(result);

        iResult = listen(ListenSocket, SOMAXCONN);
        if (iResult == SOCKET_ERROR) {
            std::cout << "listen failed: " << WSAGetLastError() << std::endl;
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }

        ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            std::cout << "accept failed: " << WSAGetLastError() << std::endl;
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }

        closesocket(ListenSocket);

        do {
            char recvbuf[512];
            int recvbuflen = 512;
            iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
            if (iResult > 0) {
                std::string recvStr(recvbuf, iResult);
                std::string sendBuf = get(recvStr);
                iResult = send(ClientSocket, sendBuf.c_str(), sendBuf.length(), 0);
                if (iResult == SOCKET_ERROR) {
                    std::cout << "send failed: " << WSAGetLastError() << std::endl;
                    closesocket(ClientSocket);
                    WSACleanup();
                    return 1;
                }
                iResult = shutdown(ClientSocket, SD_SEND);
                if (iResult == SOCKET_ERROR) {
                    std::cout << "shutdown failed: " << WSAGetLastError() << std::endl;
                    closesocket(ClientSocket);
                    WSACleanup();
                    return 1;
                }
            }
            else {
                std::cout << "recv failed: " << WSAGetLastError() << std::endl;
                closesocket(ClientSocket);
                WSACleanup();
                return 1;
            }
        } while (iResult > 0);

    }

    return 0;
}