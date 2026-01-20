#include "mainwindow.h"

#include <QVBoxLayout>

#include "client_list_widget.h"
#include "server_status_widget.h"

namespace veil::gui {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      statusWidget_(new ServerStatusWidget(this)),
      clientListWidget_(new ClientListWidget(this)) {
  setupUi();
  applyDarkTheme();
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUi() {
  setWindowTitle("VEIL VPN Server");
  setMinimumSize(800, 600);
  resize(1024, 768);

  auto* centralWidget = new QWidget(this);
  auto* layout = new QVBoxLayout(centralWidget);
  layout->addWidget(statusWidget_);
  layout->addWidget(clientListWidget_);

  setCentralWidget(centralWidget);
}

void MainWindow::applyDarkTheme() {
  setStyleSheet(R"(
    QMainWindow, QWidget {
      background-color: #1a1d23;
      color: #eceff4;
    }
  )");
}

}  // namespace veil::gui
