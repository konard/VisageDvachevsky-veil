#include "connection_widget.h"

#include <QGroupBox>
#include <QVBoxLayout>

namespace veil::gui {

ConnectionWidget::ConnectionWidget(QWidget* parent) : QWidget(parent) {
  setupUi();
}

void ConnectionWidget::setupUi() {
  auto* layout = new QVBoxLayout(this);
  layout->setSpacing(20);
  layout->setContentsMargins(40, 40, 40, 40);

  // Status card
  auto* statusGroup = new QGroupBox(this);
  auto* statusLayout = new QVBoxLayout(statusGroup);
  statusLabel_ = new QLabel("● Disconnected", statusGroup);
  statusLabel_->setAlignment(Qt::AlignCenter);
  statusLabel_->setStyleSheet("font-size: 20px; font-weight: 600;");
  statusLayout->addWidget(statusLabel_);
  statusGroup->setMinimumHeight(100);
  layout->addWidget(statusGroup);

  // Connect button
  connectButton_ = new QPushButton("Connect", this);
  connectButton_->setMinimumHeight(50);
  connect(connectButton_, &QPushButton::clicked, this, &ConnectionWidget::onConnectClicked);
  layout->addWidget(connectButton_);

  // Session info
  auto* sessionGroup = new QGroupBox("Session Info", this);
  auto* sessionLayout = new QVBoxLayout(sessionGroup);

  sessionIdLabel_ = new QLabel("Session ID: —", sessionGroup);
  sessionIdLabel_->setStyleSheet("font-family: monospace;");
  sessionLayout->addWidget(sessionIdLabel_);

  serverLabel_ = new QLabel("Server: vpn.example.com:4433", sessionGroup);
  serverLabel_->setStyleSheet("font-family: monospace;");
  sessionLayout->addWidget(serverLabel_);

  latencyLabel_ = new QLabel("Latency: —", sessionGroup);
  sessionLayout->addWidget(latencyLabel_);

  throughputLabel_ = new QLabel("TX / RX: 0 KB/s / 0 KB/s", sessionGroup);
  sessionLayout->addWidget(throughputLabel_);

  uptimeLabel_ = new QLabel("Uptime: —", sessionGroup);
  sessionLayout->addWidget(uptimeLabel_);

  layout->addWidget(sessionGroup);

  // Spacer
  layout->addStretch();

  // Settings button
  settingsButton_ = new QPushButton("⚙ Settings", this);
  settingsButton_->setStyleSheet("background: #252932; padding: 12px;");
  connect(settingsButton_, &QPushButton::clicked, this, &ConnectionWidget::settingsRequested);
  layout->addWidget(settingsButton_);
}

void ConnectionWidget::onConnectClicked() {
  // Toggle connection state
  connected_ = !connected_;
  updateStatus();

  // TODO: Send connect/disconnect command via IPC
}

void ConnectionWidget::updateStatus() {
  if (connected_) {
    statusLabel_->setText("● Connected ✓");
    statusLabel_->setStyleSheet("font-size: 20px; font-weight: 600; color: #38e2c7;");
    connectButton_->setText("Disconnect");
    connectButton_->setStyleSheet("background: #ff6b6b; padding: 16px 32px; "
                                  "border-radius: 12px; color: white; font-size: 16px;");
    sessionIdLabel_->setText("Session ID: 0x9abc123...");
    latencyLabel_->setText("Latency: 25 ms");
    throughputLabel_->setText("TX / RX: 1.2 MB/s / 3.4 MB/s");
    uptimeLabel_->setText("Uptime: 00:05:30");
  } else {
    statusLabel_->setText("● Disconnected");
    statusLabel_->setStyleSheet("font-size: 20px; font-weight: 600; color: #8fa1b3;");
    connectButton_->setText("Connect");
    connectButton_->setStyleSheet("");  // Reset to default gradient style
    sessionIdLabel_->setText("Session ID: —");
    latencyLabel_->setText("Latency: —");
    throughputLabel_->setText("TX / RX: 0 KB/s / 0 KB/s");
    uptimeLabel_->setText("Uptime: —");
  }
}

}  // namespace veil::gui
