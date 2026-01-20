#include "ipc_client_manager.h"

#include <system_error>

namespace veil::gui {

IpcClientManager::IpcClientManager()
    : client_(std::make_unique<ipc::IpcClient>(ipc::kDefaultServerSocketPath)) {
}

IpcClientManager::~IpcClientManager() = default;

bool IpcClientManager::connectToDaemon() {
  std::error_code ec;
  return client_->connect(ec);
}

}  // namespace veil::gui
