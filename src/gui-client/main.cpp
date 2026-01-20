#include <QApplication>

#include "mainwindow.h"

int main(int argc, char* argv[]) {
  QApplication app(argc, argv);

  // Set application metadata
  app.setOrganizationName("VEIL");
  app.setOrganizationDomain("veil.local");
  app.setApplicationName("VEIL Client");
  app.setApplicationVersion("0.1.0");

  // Create and show main window
  veil::gui::MainWindow window;
  window.show();

  return app.exec();
}
