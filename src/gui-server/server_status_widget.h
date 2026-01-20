#pragma once

#include <QWidget>

namespace veil::gui {

class ServerStatusWidget : public QWidget {
  Q_OBJECT

 public:
  explicit ServerStatusWidget(QWidget* parent = nullptr);

 private:
  void setupUi();
};

}  // namespace veil::gui
