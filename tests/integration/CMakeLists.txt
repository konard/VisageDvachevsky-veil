add_executable(veil_integration_handshake
  handshake_integration.cpp
)

target_link_libraries(veil_integration_handshake PRIVATE
  veil_common
  GTest::gtest_main
)

veil_set_warnings(veil_integration_handshake)

add_executable(veil_integration_transport
  transport_integration.cpp
)

target_link_libraries(veil_integration_transport PRIVATE
  veil_common
  GTest::gtest_main
)

veil_set_warnings(veil_integration_transport)

add_executable(veil_integration_reliability
  reliability_integration.cpp
)

target_link_libraries(veil_integration_reliability PRIVATE
  veil_common
  GTest::gtest_main
)

veil_set_warnings(veil_integration_reliability)

add_executable(veil_integration_security
  security_integration.cpp
)

target_link_libraries(veil_integration_security PRIVATE
  veil_common
  GTest::gtest_main
)

veil_set_warnings(veil_integration_security)

include(GoogleTest)
gtest_discover_tests(veil_integration_handshake PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
gtest_discover_tests(veil_integration_transport PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
gtest_discover_tests(veil_integration_reliability PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
gtest_discover_tests(veil_integration_security PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
