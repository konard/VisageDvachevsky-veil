#pragma once

#include <QWidget>

namespace veil::gui {

class DiagnosticsWidget : public QWidget {
  Q_OBJECT

 public:
  explicit DiagnosticsWidget(QWidget* parent = nullptr);

 signals:
  void backRequested();

 private:
  void setupUi();
};

}  // namespace veil::gui
