#include "diagnostics_widget.h"

#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

namespace veil::gui {

DiagnosticsWidget::DiagnosticsWidget(QWidget* parent) : QWidget(parent) {
  setupUi();
}

void DiagnosticsWidget::setupUi() {
  auto* layout = new QVBoxLayout(this);
  layout->setSpacing(15);
  layout->setContentsMargins(40, 20, 40, 20);

  // Back button
  auto* backButton = new QPushButton("← Back", this);
  backButton->setStyleSheet("background: #252932; padding: 8px;");
  connect(backButton, &QPushButton::clicked, this, &DiagnosticsWidget::backRequested);
  layout->addWidget(backButton);

  // Title
  auto* titleLabel = new QLabel("Diagnostics", this);
  titleLabel->setStyleSheet("font-size: 24px; font-weight: 700;");
  layout->addWidget(titleLabel);

  // Protocol Metrics
  auto* protocolGroup = new QGroupBox("Protocol Metrics", this);
  auto* protocolLayout = new QVBoxLayout(protocolGroup);
  protocolLayout->addWidget(new QLabel("Packets Sent: 12,345"));
  protocolLayout->addWidget(new QLabel("Packets Received: 12,400"));
  protocolLayout->addWidget(new QLabel("Packets Lost: 5 (0.04%)"));
  layout->addWidget(protocolGroup);

  // Reassembly Stats
  auto* reassemblyGroup = new QGroupBox("Reassembly Stats", this);
  auto* reassemblyLayout = new QVBoxLayout(reassemblyGroup);
  reassemblyLayout->addWidget(new QLabel("Fragments Received: 42"));
  reassemblyLayout->addWidget(new QLabel("Messages Reassembled: 38"));
  layout->addWidget(reassemblyGroup);

  // Live Event Log
  auto* logGroup = new QGroupBox("Live Event Log", this);
  auto* logLayout = new QVBoxLayout(logGroup);
  auto* logText = new QTextEdit(logGroup);
  logText->setReadOnly(true);
  logText->setStyleSheet("background: #252932; font-family: monospace;");
  logText->setPlainText("[14:32:05] Handshake INIT sent\n"
                        "[14:32:05] Handshake RESPONSE received\n"
                        "[14:32:05] Session established (ID=0x...)\n");
  logLayout->addWidget(logText);
  layout->addWidget(logGroup);

  // Export button
  auto* exportButton = new QPushButton("Export Diagnostics", this);
  layout->addWidget(exportButton);
}

}  // namespace veil::gui
