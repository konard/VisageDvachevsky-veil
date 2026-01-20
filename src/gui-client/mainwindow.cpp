#include "mainwindow.h"

#include <QMenuBar>
#include <QVBoxLayout>

#include "connection_widget.h"
#include "diagnostics_widget.h"
#include "ipc_client_manager.h"
#include "settings_widget.h"

namespace veil::gui {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      stackedWidget_(new QStackedWidget(this)),
      connectionWidget_(new ConnectionWidget(this)),
      settingsWidget_(new SettingsWidget(this)),
      diagnosticsWidget_(new DiagnosticsWidget(this)),
      ipcManager_(std::make_unique<IpcClientManager>()) {
  setupUi();
  setupMenuBar();
  applyDarkTheme();

  // Connect to daemon
  ipcManager_->connectToDaemon();
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUi() {
  setWindowTitle("VEIL VPN Client");
  setMinimumSize(480, 720);
  resize(480, 720);

  // Add widgets to stacked widget
  stackedWidget_->addWidget(connectionWidget_);
  stackedWidget_->addWidget(settingsWidget_);
  stackedWidget_->addWidget(diagnosticsWidget_);

  // Set central widget
  setCentralWidget(stackedWidget_);

  // Connect signals
  connect(connectionWidget_, &ConnectionWidget::settingsRequested,
          this, &MainWindow::showSettingsView);
  connect(settingsWidget_, &SettingsWidget::backRequested,
          this, &MainWindow::showConnectionView);
  connect(diagnosticsWidget_, &DiagnosticsWidget::backRequested,
          this, &MainWindow::showConnectionView);
}

void MainWindow::setupMenuBar() {
  auto* viewMenu = menuBar()->addMenu(tr("&View"));
  viewMenu->addAction(tr("&Connection"), this, &MainWindow::showConnectionView);
  viewMenu->addAction(tr("&Settings"), this, &MainWindow::showSettingsView);
  viewMenu->addAction(tr("&Diagnostics"), this, &MainWindow::showDiagnosticsView);

  auto* helpMenu = menuBar()->addMenu(tr("&Help"));
  helpMenu->addAction(tr("&About"), [this]() {
    // TODO: Show about dialog
  });
}

void MainWindow::applyDarkTheme() {
  // Apply dark theme stylesheet based on client_ui_design.md color palette
  QString stylesheet = R"(
    QMainWindow, QWidget {
      background-color: #1a1d23;
      color: #eceff4;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    }
    QPushButton {
      background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                  stop:0 #3aafff, stop:1 #38e2c7);
      border: none;
      border-radius: 12px;
      padding: 16px 32px;
      color: white;
      font-size: 16px;
      font-weight: 600;
    }
    QPushButton:hover {
      background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                  stop:0 #4abfff, stop:1 #48f2d7);
    }
    QPushButton:pressed {
      background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                  stop:0 #2a9fef, stop:1 #28d2b7);
    }
    QGroupBox {
      background-color: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      margin-top: 10px;
      padding-top: 10px;
      font-size: 15px;
    }
    QGroupBox::title {
      subcontrol-origin: margin;
      left: 10px;
      padding: 0 5px;
    }
    QLineEdit, QSpinBox {
      background-color: #252932;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 8px;
      color: #eceff4;
    }
    QCheckBox {
      spacing: 8px;
    }
    QLabel {
      color: #eceff4;
    }
  )";

  setStyleSheet(stylesheet);
}

void MainWindow::showConnectionView() {
  stackedWidget_->setCurrentWidget(connectionWidget_);
}

void MainWindow::showSettingsView() {
  stackedWidget_->setCurrentWidget(settingsWidget_);
}

void MainWindow::showDiagnosticsView() {
  stackedWidget_->setCurrentWidget(diagnosticsWidget_);
}

}  // namespace veil::gui
