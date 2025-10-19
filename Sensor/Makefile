# 컴파일러
CXX = g++
CXXFLAGS = -std=c++20 -O0 -Wall -g -I./include

# 라이브러리
LDFLAGS = -lcppkafka -lrdkafka++ -lrdkafka -lpthread -lsqlite3 -lfmt -lcrypto -lbpf -pthread -lPcap++ -lPacket++ -lCommon++ -lpcap -L/usr/lib64 -lssl -lcrypto

# 소스, 오브젝트, 실행파일
SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = sensor_executor

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
