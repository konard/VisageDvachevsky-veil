#include <QApplication>

#include "mainwindow.h"

int main(int argc, char* argv[]) {
  QApplication app(argc, argv);

  app.setOrganizationName("VEIL");
  app.setOrganizationDomain("veil.local");
  app.setApplicationName("VEIL Server");
  app.setApplicationVersion("0.1.0");

  veil::gui::MainWindow window;
  window.show();

  return app.exec();
}
