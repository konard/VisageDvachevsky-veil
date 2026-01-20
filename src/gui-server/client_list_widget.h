#pragma once

#include <QWidget>

namespace veil::gui {

class ClientListWidget : public QWidget {
  Q_OBJECT

 public:
  explicit ClientListWidget(QWidget* parent = nullptr);

 private:
  void setupUi();
};

}  // namespace veil::gui
