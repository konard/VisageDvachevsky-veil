#pragma once

#include <memory>

#include "common/ipc/ipc_socket.h"

namespace veil::gui {

class IpcClientManager {
 public:
  IpcClientManager();
  ~IpcClientManager();

  bool connectToDaemon();

 private:
  std::unique_ptr<ipc::IpcClient> client_;
};

}  // namespace veil::gui
