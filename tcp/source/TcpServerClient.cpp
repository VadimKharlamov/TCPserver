#include "../include/TcpServer.h"

using namespace stcp;
#include <iostream>

DataBuffer TcpServer::Client::loadData() {
  if(_status != SocketStatus::connected) return DataBuffer();
  using namespace std::chrono_literals;
  DataBuffer buffer;
  uint32_t size;
  int err;

  int answ = recv(socket, (char*)&size, sizeof(size), MSG_DONTWAIT);

  if(!answ) {
    disconnect();
    return DataBuffer();
  } else if(answ == -1) {
      SockLen_t len = sizeof (err);
      getsockopt (socket, SOL_SOCKET, SO_ERROR, &err, &len);
      if(!err) err = errno;


    switch (err) {
      case 0: return DataBuffer();
      case ETIMEDOUT:
      case ECONNRESET:
      case EPIPE:
        disconnect();
        [[fallthrough]];
      case EAGAIN: return DataBuffer();
      default:
        disconnect();
        std::cerr << "Unhandled error!\n"
                    << "Code: " << err << " Err: " << std::strerror(err) << '\n';
      return DataBuffer();
    }
  }

  if(!size) return DataBuffer();
  buffer.resize(size);
  recv(socket, reinterpret_cast<char*>(buffer.data()), buffer.size(), 0);
  return buffer;
}


TcpClientBase::status TcpServer::Client::disconnect() {
  _status = status::disconnected;
  if(socket == -1) return _status;
  shutdown(socket, SD_BOTH);
  close(socket);
  socket = -1;
  return _status;
}

bool TcpServer::Client::sendData(const void* buffer, const size_t size) const {
  if(_status != SocketStatus::connected) return false;

  void* send_buffer = malloc(size + sizeof (uint32_t));
  memcpy(reinterpret_cast<char*>(send_buffer) + sizeof(uint32_t), buffer, size);
  *reinterpret_cast<uint32_t*>(send_buffer) = size;

  if(send(socket, reinterpret_cast<char*>(send_buffer), size + sizeof (int), 0) < 0) {
    free(send_buffer);
    return false;
  }

  free(send_buffer);
  return true;
}

TcpServer::Client::Client(Socket socket, SocketAddr_in address)
  : address(address), socket(socket) {}


TcpServer::Client::~Client() {
  if(socket == -1) return;
  shutdown(socket, SD_BOTH);
  close(socket);
}

uint32_t TcpServer::Client::getHost() const {return address.sin_addr.s_addr;}
uint16_t TcpServer::Client::getPort() const {return address.sin_port;}

