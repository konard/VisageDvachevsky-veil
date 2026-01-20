# VEIL Client GUI Application (Qt/C++)

find_package(Qt6 COMPONENTS Core Widgets Network QUIET)

if(NOT Qt6_FOUND)
  message(STATUS "Qt6 not found, client GUI will not be built")
  message(STATUS "To build the GUI, install Qt6: sudo apt-get install qt6-base-dev")
  return()
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

add_executable(veil-client-gui
  main.cpp
  mainwindow.cpp
  mainwindow.h
  connection_widget.cpp
  connection_widget.h
  settings_widget.cpp
  settings_widget.h
  diagnostics_widget.cpp
  diagnostics_widget.h
  ipc_client_manager.cpp
  ipc_client_manager.h
)

target_link_libraries(veil-client-gui
  PRIVATE
    veil_common
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
)

veil_set_warnings(veil-client-gui)

install(TARGETS veil-client-gui
  RUNTIME DESTINATION bin
)
