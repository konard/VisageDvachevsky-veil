#include "settings_widget.h"

#include <QCheckBox>
#include <QComboBox>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace veil::gui {

SettingsWidget::SettingsWidget(QWidget* parent) : QWidget(parent) {
  setupUi();
}

void SettingsWidget::setupUi() {
  auto* layout = new QVBoxLayout(this);
  layout->setSpacing(20);
  layout->setContentsMargins(40, 20, 40, 20);

  // Back button
  auto* backButton = new QPushButton("← Back", this);
  backButton->setStyleSheet("background: #252932; padding: 8px;");
  connect(backButton, &QPushButton::clicked, this, &SettingsWidget::backRequested);
  layout->addWidget(backButton);

  // Title
  auto* titleLabel = new QLabel("Settings", this);
  titleLabel->setStyleSheet("font-size: 24px; font-weight: 700;");
  layout->addWidget(titleLabel);

  // Server Configuration
  auto* serverGroup = new QGroupBox("Server Configuration", this);
  auto* serverLayout = new QVBoxLayout(serverGroup);
  serverLayout->addWidget(new QLabel("Server Address:"));
  auto* serverEdit = new QLineEdit("vpn.example.com", serverGroup);
  serverLayout->addWidget(serverEdit);
  serverLayout->addWidget(new QLabel("Port:"));
  auto* portSpin = new QSpinBox(serverGroup);
  portSpin->setRange(1, 65535);
  portSpin->setValue(4433);
  serverLayout->addWidget(portSpin);
  layout->addWidget(serverGroup);

  // Routing
  auto* routingGroup = new QGroupBox("Routing", this);
  auto* routingLayout = new QVBoxLayout(routingGroup);
  routingLayout->addWidget(new QCheckBox("Route all traffic through VPN"));
  routingLayout->addWidget(new QCheckBox("Split tunnel mode"));
  layout->addWidget(routingGroup);

  // Connection
  auto* connGroup = new QGroupBox("Connection", this);
  auto* connLayout = new QVBoxLayout(connGroup);
  connLayout->addWidget(new QCheckBox("Auto-reconnect on disconnect"));
  layout->addWidget(connGroup);

  // DPI Bypass Mode
  auto* dpiGroup = new QGroupBox("DPI Bypass Mode", this);
  auto* dpiLayout = new QVBoxLayout(dpiGroup);

  dpiLayout->addWidget(new QLabel("Select traffic obfuscation mode:"));

  auto* dpiModeCombo = new QComboBox(dpiGroup);
  dpiModeCombo->addItem("IoT Mimic");
  dpiModeCombo->addItem("QUIC-Like");
  dpiModeCombo->addItem("Random-Noise Stealth");
  dpiModeCombo->addItem("Trickle Mode");
  dpiModeCombo->setCurrentIndex(0);
  dpiLayout->addWidget(dpiModeCombo);

  auto* dpiDescLabel = new QLabel(this);
  dpiDescLabel->setWordWrap(true);
  dpiDescLabel->setStyleSheet("color: #88c0d0; font-size: 11px; padding: 8px;");
  dpiDescLabel->setText("Simulates IoT sensor traffic. Good balance of stealth and performance.");
  dpiLayout->addWidget(dpiDescLabel);

  // Update description when mode changes
  connect(dpiModeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
          [dpiDescLabel](int index) {
            const char* descriptions[] = {
                "Simulates IoT sensor traffic. Good balance of stealth and performance.",
                "Mimics modern HTTP/3 traffic. Best for high-throughput scenarios.",
                "Maximum unpredictability. Use in extreme censorship scenarios.",
                "Low-and-slow traffic. Maximum stealth but limited bandwidth (10-50 kbit/s)."};
            if (index >= 0 && index < 4) {
              dpiDescLabel->setText(descriptions[index]);
            }
          });

  layout->addWidget(dpiGroup);

  // Advanced
  auto* advGroup = new QGroupBox("Advanced", this);
  auto* advLayout = new QVBoxLayout(advGroup);
  advLayout->addWidget(new QCheckBox("Enable obfuscation"));
  advLayout->addWidget(new QCheckBox("Verbose logging"));
  advLayout->addWidget(new QCheckBox("Developer mode"));
  layout->addWidget(advGroup);

  layout->addStretch();

  // Save button
  auto* saveButton = new QPushButton("Save Changes", this);
  layout->addWidget(saveButton);
}

}  // namespace veil::gui
