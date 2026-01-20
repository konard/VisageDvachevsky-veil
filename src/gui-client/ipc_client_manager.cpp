#include "ipc_client_manager.h"

#include <system_error>

namespace veil::gui {

IpcClientManager::IpcClientManager()
    : client_(std::make_unique<ipc::IpcClient>()) {
  client_->on_message([this](const ipc::Message& msg) {
    handleMessage(msg);
  });

  client_->on_connection_change([this](bool connected) {
    handleConnectionChange(connected);
  });
}

IpcClientManager::~IpcClientManager() {
  disconnect();
}

bool IpcClientManager::connectToDaemon() {
  std::error_code ec;
  if (!client_->connect(ec)) {
    // Failed to connect - daemon may not be running
    return false;
  }
  return true;
}

void IpcClientManager::disconnect() {
  client_->disconnect();
}

bool IpcClientManager::isConnected() const {
  return client_->is_connected();
}

void IpcClientManager::handleMessage(const ipc::Message& msg) {
  // TODO: Handle incoming messages (events, responses)
  // Update GUI state based on daemon events
  (void)msg;
}

void IpcClientManager::handleConnectionChange(bool connected) {
  // TODO: Update GUI to reflect connection status
  (void)connected;
}

}  // namespace veil::gui
