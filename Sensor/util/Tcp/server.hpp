#ifndef TCP_UTIL_H
#define TCP_UTIL_H

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>
#include <atomic>
#include <thread>
#include <mutex>

namespace NDR
{
	namespace Util
	{
		namespace Tcp
		{
			class TcpServer
			{
			public:
            /*
                TcpServer(),
                ~TcpServer(),

                bool OpenServer(ClientHandler handler)
                bool Close_Server()

                bool Disconnect_Client(int clientfd)
                bool Send( int clientfd, const std::vector<unsigned char>& inputdata)
                bool Recv( int clientfd, const std::vector<unsigned char>& outputdata)

            */
				TcpServer(const std::string Serverip, int Serverport) : Serverip(Serverip), Serverport(Serverport){}
				~TcpServer(){ Close_Server(); }

                using ClientHandler = std::function<void(int, std::string, int)>;  // 클라이언트 연결 시, 호출되는 콜백함수 인자: int -> clientfd
				bool OpenServer(ClientHandler handler)
                {
                    // Tcp 소켓 Open
                    serverfd = socket(AF_INET, SOCK_STREAM, 0);
                    if (serverfd == -1) {
                        perror("socket");
                        return false;
                    }

                    sockaddr_in server_addr{};
                    server_addr.sin_family = AF_INET;
                    server_addr.sin_port = htons(Serverport);
                    server_addr.sin_addr.s_addr = inet_addr(Serverip.c_str());

                    int opt = 1;
                    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

                    if (bind(serverfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
                        perror("bind");
                        close(serverfd);
                        return false;
                    }

                    if (listen(serverfd, SOMAXCONN) < 0) {
                        perror("listen");
                        close(serverfd);
                        return false;
                    }

                    is_waiting_client = true;
                    waiting_client_thread = std::thread(
                        [this, callback = handler]()
                        {
                            while (this->is_waiting_client) {
                                sockaddr_in client_addr{};
                                socklen_t addrlen = sizeof(client_addr);
                                std::cout << "TCP SERVER {"<< this->Serverip << ":" << this->Serverport << "} openned" << std::endl;
                                int clientfd = accept(this->serverfd, (struct sockaddr*)&client_addr, &addrlen);
                                if (clientfd < 0) {
                                    perror("accept");
                                    continue;
                                }

                                std::cout << "Client connected: " << inet_ntoa(client_addr.sin_addr) << std::endl;

                                
                                {
                                    // 단, 서버 종료시 clientfd 강제 연결해제
                                    std::lock_guard<std::mutex> lock(alive_clients_mtx);
                                    this->alive_clients.push_back(clientfd);
                                }

                                // 클라이언트 연결 시 외부에서 전달한 핸들러 실행
                                /*
                                    clientfd 송수신 및 fd관리는 이제 callback() 스레드에서 처리해야한다
                                */
                                callback(clientfd, inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port));
                                
                            }
                        }
                    );
                    return true;
                }
                bool Close_Server()
                {
                    std::cout << "Close TCP Server" << std::endl;
                    if(serverfd < 0 || !is_waiting_client)
                        return false;
                    
                    is_waiting_client = false;
                    shutdown(serverfd, SHUT_RDWR);// accept 해제
                    close(serverfd);
                    if(waiting_client_thread.joinable())
                    {
                        waiting_client_thread.join();

                        std::lock_guard<std::mutex> lock(alive_clients_mtx);
                        for(auto client : alive_clients)
                            close(client);
                        alive_clients.clear();
                    }
                    return true;
                }
                bool Disconnect_Client(int clientfd)
                {
                    if(clientfd < 0)
                        return false;

                    std::lock_guard<std::mutex> lock(alive_clients_mtx);
                    for(auto it = alive_clients.begin(); it != alive_clients.end(); ++it) {
                        if(*it == clientfd) {
                            close(clientfd);
                            alive_clients.erase(it);
                            return true;
                        }
                    }
                    return false;
                }
				bool Send( int clientfd, const std::vector<unsigned char>& inputdata)
                {
                    /*
                        4바이트 고정 길이(다음 올 실제데이터 길이)를 먼저 전송하고,
                        실제 데이터를 전달
                    */
                    uint32_t netDataSize = static_cast<uint32_t>(inputdata.size());

                    // 1. 데이터 길이(4바이트) 전송
                    ssize_t sent = send(clientfd, &netDataSize, sizeof(netDataSize), 0);
                    if (sent != sizeof(netDataSize)) {
                        perror("send length");
                        return false;
                    }

                    // 2. 실제 데이터 전송
                    size_t totalSent = 0;
                    while (totalSent < netDataSize) {
                        ssize_t n = send(clientfd, inputdata.data() + totalSent, netDataSize - totalSent, 0);
                        if (n <= 0) {
                            perror("send data");
                            return false;
                        }
                        totalSent += n;
                    }
                    return true;
                }
				bool Receive(int clientfd, std::vector<unsigned char>& outbuffer)
                {
                    uint32_t netDataSize = 0;
                    ssize_t received = recv(clientfd, &netDataSize, sizeof(netDataSize), MSG_WAITALL);
                    if (received <= 0) {
                        perror("recv length");
                        return false;
                    }

                    // netDataSize 이 값은 "리틀 엔디언"

                    outbuffer.resize(netDataSize);
                    size_t totalReceived = 0;
                    while (totalReceived < netDataSize) {
                        ssize_t n = recv(clientfd, outbuffer.data() + totalReceived, netDataSize - totalReceived, 0);
                        if (n <= 0) {
                            perror("recv data");
                            return false;
                        }
                        totalReceived += n;
                    }
                    return true;
                }


			private:
				std::string Serverip;
				int Serverport;

                int serverfd = -1;

                std::atomic<bool> is_waiting_client = false;
                std::thread waiting_client_thread;

                std::mutex alive_clients_mtx;
                std::vector<int> alive_clients;

			};
		}
	}
}

#endif