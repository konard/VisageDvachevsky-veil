#pragma once

#include <QMainWindow>

namespace veil::gui {

class ServerStatusWidget;
class ClientListWidget;

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow() override;

 private:
  void setupUi();
  void applyDarkTheme();

  ServerStatusWidget* statusWidget_;
  ClientListWidget* clientListWidget_;
};

}  // namespace veil::gui
