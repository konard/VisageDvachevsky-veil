#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <memory>

namespace veil::gui {

class ConnectionWidget;
class SettingsWidget;
class DiagnosticsWidget;
class IpcClientManager;

class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow() override;

 private slots:
  void showConnectionView();
  void showSettingsView();
  void showDiagnosticsView();

 private:
  void setupUi();
  void setupMenuBar();
  void applyDarkTheme();

  QStackedWidget* stackedWidget_;
  ConnectionWidget* connectionWidget_;
  SettingsWidget* settingsWidget_;
  DiagnosticsWidget* diagnosticsWidget_;
  std::unique_ptr<IpcClientManager> ipcManager_;
};

}  // namespace veil::gui
