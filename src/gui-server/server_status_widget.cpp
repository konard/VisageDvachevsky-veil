#include "server_status_widget.h"

#include <QGroupBox>
#include <QLabel>
#include <QVBoxLayout>

namespace veil::gui {

ServerStatusWidget::ServerStatusWidget(QWidget* parent) : QWidget(parent) {
  setupUi();
}

void ServerStatusWidget::setupUi() {
  auto* layout = new QVBoxLayout(this);

  auto* statusGroup = new QGroupBox("Server Status", this);
  auto* statusLayout = new QVBoxLayout(statusGroup);
  statusLayout->addWidget(new QLabel("Status: Running"));
  statusLayout->addWidget(new QLabel("Listen Port: 4443"));
  statusLayout->addWidget(new QLabel("Active Clients: 3 / 100"));
  statusLayout->addWidget(new QLabel("Uptime: 02:34:56"));

  layout->addWidget(statusGroup);
}

}  // namespace veil::gui
