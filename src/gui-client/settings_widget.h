#pragma once

#include <QWidget>

namespace veil::gui {

class SettingsWidget : public QWidget {
  Q_OBJECT

 public:
  explicit SettingsWidget(QWidget* parent = nullptr);

 signals:
  void backRequested();

 private:
  void setupUi();
};

}  // namespace veil::gui
