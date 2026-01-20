#pragma once

#include <memory>

#include "common/ipc/ipc_socket.h"

namespace veil::gui {

class IpcClientManager {
 public:
  IpcClientManager();
  ~IpcClientManager();

  bool connectToDaemon();
  void disconnect();

  bool isConnected() const;

 private:
  void handleMessage(const ipc::Message& msg);
  void handleConnectionChange(bool connected);

  std::unique_ptr<ipc::IpcClient> client_;
};

}  // namespace veil::gui
