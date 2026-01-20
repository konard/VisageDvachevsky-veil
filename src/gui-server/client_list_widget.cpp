#include "client_list_widget.h"

#include <QGroupBox>
#include <QTableWidget>
#include <QVBoxLayout>

namespace veil::gui {

ClientListWidget::ClientListWidget(QWidget* parent) : QWidget(parent) {
  setupUi();
}

void ClientListWidget::setupUi() {
  auto* layout = new QVBoxLayout(this);

  auto* clientsGroup = new QGroupBox("Connected Clients", this);
  auto* clientsLayout = new QVBoxLayout(clientsGroup);

  auto* table = new QTableWidget(0, 5, clientsGroup);
  table->setHorizontalHeaderLabels({"Session ID", "Tunnel IP", "Endpoint", "Uptime", "Traffic"});
  clientsLayout->addWidget(table);

  layout->addWidget(clientsGroup);
}

}  // namespace veil::gui
