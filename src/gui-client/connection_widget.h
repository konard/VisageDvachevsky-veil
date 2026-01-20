#pragma once

#include <QLabel>
#include <QPushButton>
#include <QWidget>

namespace veil::gui {

class ConnectionWidget : public QWidget {
  Q_OBJECT

 public:
  explicit ConnectionWidget(QWidget* parent = nullptr);

 signals:
  void settingsRequested();

 private slots:
  void onConnectClicked();
  void updateStatus();

 private:
  void setupUi();

  QLabel* statusLabel_;
  QLabel* sessionIdLabel_;
  QLabel* serverLabel_;
  QLabel* latencyLabel_;
  QLabel* throughputLabel_;
  QLabel* uptimeLabel_;
  QPushButton* connectButton_;
  QPushButton* settingsButton_;

  bool connected_{false};
};

}  // namespace veil::gui
