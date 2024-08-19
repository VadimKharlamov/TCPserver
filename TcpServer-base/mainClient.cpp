#include "tcp/include/TcpClient.h"

#include <iostream>
#include <stdlib.h>
#include <thread>
#include <list>
#include <unistd.h>

using namespace stcp;
enum class ActionCode : unsigned char {
  register_user = 0x00,
  authorize = 0x01,
  ready = 0x02,
  exit = 0x03,
  task_done = 0x04
};

enum class ResponseCode : unsigned char {
  auth_ok = 0x00,
  auth_fail = 0x01,
  start_ok = 0x02,
  start_fail = 0x03,
  incoming_task = 0x04,
  access_denied = 0xFF
};

std::string getHostStr(uint32_t ip, uint16_t port) {
    return std::string() + std::to_string(int(reinterpret_cast<char*>(&ip)[0])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[1])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[2])) + '.' +
            std::to_string(int(reinterpret_cast<char*>(&ip)[3])) + ':' +
            std::to_string( port );
}


template<typename T>
T extract(DataBuffer::iterator& it) {
  T result = *reinterpret_cast<T*>(&*it);
  it += sizeof(T);
  return result;
}


std::string extractString(DataBuffer::iterator& it) {
  uint64_t string_size = extract<uint64_t>(it);
  std::string string(reinterpret_cast<std::string::value_type*>(&*it), string_size);
  it += string_size;
  return string;
}

template<typename T>
void append(DataBuffer& buffer, const T& data) {
  const uint8_t* data_it = reinterpret_cast<const uint8_t*>(&data);
  for(std::size_t data_size = sizeof(T); data_size; (--data_size, ++data_it))
    buffer.push_back(*data_it);
}

void appendString(DataBuffer& buffer, std::string_view str) {
  append<uint64_t>(buffer, str.size());
  for(const char& ch : str)
    buffer.push_back(reinterpret_cast<const uint8_t&>(ch));
}

ThreadPool thread_pool;
TcpClient client(&thread_pool);
uint16_t act_sequence = 0;

std::mutex auth_mutex;
std::mutex start_mutex;
std::condition_variable auth_cv;
std::condition_variable start_cv;
uint16_t auth_act_sequence;
uint16_t start_act_sequence;
ResponseCode auth_response;
ResponseCode start_response;

int tasks;

ResponseCode waitAuth(uint16_t act_sequence) {
  std::unique_lock lk(auth_mutex);
  auth_cv.wait(lk, [&act_sequence]{ return auth_act_sequence == act_sequence; });
  return auth_response;
}

ResponseCode waitStart(uint16_t act_sequence) {
  std::unique_lock lk(start_mutex);
  start_cv.wait(lk, [&act_sequence]{ return start_act_sequence == act_sequence; });
  return start_response;
}

void clearConsole() {
  std::cout << "\x1B[2J\x1B[H";
}

void cli() {
  while (tasks != 0) { 
    std::cout << "Processing... " << tasks << " left\n";
    sleep(5);
    tasks--;
  }


  DataBuffer buffer;
  buffer.reserve(
    sizeof(uint16_t) +    // sequence
    sizeof(ActionCode)    // code
                          // + maybe result struct 
  );
  append(buffer, act_sequence++);
  append(buffer, ActionCode::task_done);

  client.sendData(buffer.data(), buffer.size());
  std::cout << "Task done!\n";
}

void reciveHandler(DataBuffer data) {
  auto data_it = data.begin();
  uint16_t act_sequence = extract<uint16_t>(data_it);
  ResponseCode response_code = extract<ResponseCode>(data_it);

  switch (response_code) {
  case ResponseCode::auth_ok:
  case ResponseCode::auth_fail:
  {
    std::unique_lock lk(auth_mutex);
    auth_act_sequence = act_sequence;
    auth_response = response_code;
  }
  auth_cv.notify_one();
  return;

  case ResponseCode::start_ok:
  case ResponseCode::start_fail:
  {
    std::unique_lock lk(start_mutex);
    start_act_sequence = act_sequence;
    start_response = response_code;
  }
  start_cv.notify_one();
  return;

  case ResponseCode::incoming_task: {
    tasks = std::stoi(extractString(data_it));
    std::cout << "New task!\n";
    thread_pool.addJob(cli);
    return;
  }
  case ResponseCode::access_denied: {
    std::cout << "Access denied\n";
    return;
  }
  }
}


void computeCheck() {
  do {
    std::string input;
    std::clog << "Start compute process?:\n"
                 "1. Yes\n"
                 "2. No\n"
                 "> ";
    int action_number;
    std::getline(std::cin, input);
    action_number = std::stoi(input);

    if(action_number > 2 || action_number < 1) continue;

    DataBuffer buffer;
    buffer.reserve(
      sizeof(uint16_t) + 
      sizeof(ActionCode) 
    );
    append(buffer, act_sequence);
    append(buffer, action_number == 1 ? ActionCode::ready : ActionCode::exit);

    client.sendData(buffer.data(), buffer.size());
    if(waitStart(act_sequence++) == ResponseCode::start_ok) {
      std::cout << "Ready to start\n";
      break;
    }
    std::cerr << "Start failed!\n";

  } while(true);
}

void auth() {
  do {
    std::string input;
    std::clog << "Select action:\n"
                 "1. Authentication\n"
                 "2. Registration\n"
                 "> ";
    int action_number;
    std::getline(std::cin, input);
    action_number = std::stoi(input);

    if(action_number > 2 || action_number < 1) continue;
    std::string login, password;

    std::clog << "Login: "; std::getline(std::cin, login);
    std::clog << "Password: "; std::getline(std::cin, password);

    DataBuffer buffer;
    buffer.reserve(
      sizeof(uint16_t) +     // sequence
      sizeof(ActionCode) +  // code
      sizeof(uint64_t) +    // login_size
      login.size() +        // login
      sizeof(uint64_t) +    // password_size
      password.size()       // password
    );
    append(buffer, act_sequence);
    append(buffer, action_number == 1 ? ActionCode::authorize : ActionCode::register_user);
    appendString(buffer, login);
    appendString(buffer, password);

    client.sendData(buffer.data(), buffer.size());
    if(waitAuth(act_sequence++) == ResponseCode::auth_ok) break;
    std::cerr << "Authentication failed!\n";

  } while(true);

  thread_pool.addJob(computeCheck);
}



int main(int, char**) {
  if(client.connectTo(LOCALHOST_IP, 8081) == SocketStatus::connected) {
    std::clog << "Client connected\n";
    thread_pool.addJob(auth);
    client.setHandler(reciveHandler);
    thread_pool.join();
  } else {
    std::cerr << "Client isn't connected\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
