#include "../include/TcpServer.h"
#include <chrono>
#include <cstring>
#include <mutex>

using namespace stcp;

TcpServer::TcpServer(const uint16_t port,
                     KeepAliveConfig ka_conf,
                     handler_function_t handler,
                     con_handler_function_t connect_hndl,
                     con_handler_function_t disconnect_hndl,
                     unsigned int thread_count
                     )
  : port(port),
    handler(handler),
    connect_hndl(connect_hndl),
    disconnect_hndl(disconnect_hndl),
    thread_pool(thread_count),
    ka_conf(ka_conf)
    {}

TcpServer::~TcpServer() {
  if(_status == status::up)
    stop();
}

void TcpServer::setHandler(TcpServer::handler_function_t handler) {this->handler = handler;}

uint16_t TcpServer::getPort() const {return port;}
uint16_t TcpServer::setPort( const uint16_t port) {
	this->port = port;
	start();
	return port;
}

TcpServer::status TcpServer::start() {
  int flag;
  if(_status == status::up) stop();

  SocketAddr_in address;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);
  address.sin_family = AF_INET;


  if((serv_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
     return _status = status::err_socket_init;

  if(flag = true;
     (setsockopt(serv_socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1) ||
     (bind(serv_socket, (struct sockaddr*)&address, sizeof(address)) < 0))
     return _status = status::err_socket_bind;

  if(listen(serv_socket, SOMAXCONN) < 0)
    return _status = status::err_socket_listening;
  _status = status::up;
  thread_pool.addJob([this]{handlingAcceptLoop();});
  thread_pool.addJob([this]{waitingDataLoop();});
  return _status;
}

void TcpServer::stop() {
  thread_pool.dropUnstartedJobs();
  _status = status::close;
  close(serv_socket);
  client_list.clear();
}

void TcpServer::joinLoop() {thread_pool.join();}

bool TcpServer::connectTo(uint32_t host, uint16_t port, con_handler_function_t connect_hndl) {
  Socket client_socket;
  SocketAddr_in address;
  if((client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) return false;

  new(&address) SocketAddr_in;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = host;
  address.sin_addr.s_addr = host;

  address.sin_port = htons(port);

  if(connect(client_socket, (sockaddr *)&address, sizeof(address))!= 0) {
   close(client_socket);
    return false;
  }

  if(!enableKeepAlive(client_socket)) {
    shutdown(client_socket, 0);
    close(client_socket);
  }

  std::unique_ptr<Client> client = std::make_unique<Client>(client_socket, address);
  connect_hndl(*client);
  client_mutex.lock();
  client_list.emplace(std::move(client));
  client_mutex.unlock();
  return true;
}

void TcpServer::sendData(const void* buffer, const size_t size) {
  for(const std::unique_ptr<Client>& client : client_list) client->sendData(buffer, size);
}

bool TcpServer::sendDataBy(uint32_t host, uint16_t port, const void* buffer, const size_t size) {
  if(auto client_it = client_list.find(ClientKey{host, port}); client_it != client_list.cend()) {
    (*client_it)->sendData(buffer, size);
    return true;
  } return false;
}

bool TcpServer::disconnectBy(uint32_t host, uint16_t port) {
  bool client_is_disconnected = false;
  for(const std::unique_ptr<Client>& client : client_list)
    if(client->getHost() == host &&
       client->getPort() == port) {
      client->disconnect();
      client_is_disconnected = true;
    }
  return client_is_disconnected;
}

void TcpServer::disconnectAll() {
  for(const std::unique_ptr<Client>& client : client_list)
    client->disconnect();
}

void TcpServer::handlingAcceptLoop() {
  SockLen_t addrlen = sizeof(SocketAddr_in);
  SocketAddr_in client_addr;
  if (Socket client_socket =
      accept4(serv_socket, (struct sockaddr*)&client_addr, &addrlen, SOCK_NONBLOCK);
      client_socket >= 0 && _status == status::up) {
    if(enableKeepAlive(client_socket)) {
      std::unique_ptr<Client> client(new Client(client_socket, client_addr));
      connect_hndl(*client);
      client_mutex.lock();
      client_list.emplace(std::move(client));
      client_mutex.unlock();
    } else {
      shutdown(client_socket, 0);
      close(client_socket);
    }
  }

  if(_status == status::up)
    thread_pool.addJob([this](){handlingAcceptLoop();});
}

void TcpServer::waitingDataLoop() {
  [this]{
    std::lock_guard lock(client_mutex);
    for(auto it = client_list.begin(), end = client_list.end(); it != end; ++it) {

      do {
        auto& client = *it;

        if(DataBuffer data = client->loadData(); !data.empty()) {

          thread_pool.addJob([this, _data = std::move(data), &client = *client]{
            client.access_mtx.lock();
            handler(std::move(_data), client);
            client.access_mtx.unlock();
          });

        } else if(client->_status == SocketStatus::disconnected) {

          thread_pool.addJob([this, it = it++]{
            client_mutex.lock();
            auto client_node = client_list.extract(it);
            client_mutex.unlock();
            client_node.value()->access_mtx.lock();
            disconnect_hndl(*client_node.value());
            client_node.value()->access_mtx.unlock();
          });

          if(it == client_list.cend()) return;
          else continue;
        }

        break;
      } while(true);

    }
  }();

  if(_status == status::up) thread_pool.addJob([this](){waitingDataLoop();});
}

bool TcpServer::enableKeepAlive(Socket socket) {
  int flag = 1;
  if(setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) == -1) return false;
  if(setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, &ka_conf.ka_idle, sizeof(ka_conf.ka_idle)) == -1) return false;
  if(setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, &ka_conf.ka_intvl, sizeof(ka_conf.ka_intvl)) == -1) return false;
  if(setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, &ka_conf.ka_cnt, sizeof(ka_conf.ka_cnt)) == -1) return false;
  return true;
}
