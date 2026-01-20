add_executable(veil_unit_tests
  random_tests.cpp
  config_tests.cpp
  crypto_tests.cpp
  packet_tests.cpp
  replay_window_tests.cpp
  handshake_tests.cpp
  handshake_replay_cache_tests.cpp
  ack_bitmap_tests.cpp
  reorder_buffer_tests.cpp
  fragment_reassembly_tests.cpp
  udp_socket_tests.cpp
  mux_codec_tests.cpp
  retransmit_buffer_tests.cpp
  ack_scheduler_tests.cpp
  transport_session_tests.cpp
  timer_heap_tests.cpp
  obfuscation_tests.cpp
  tun_device_tests.cpp
  routing_tests.cpp
  mtu_discovery_tests.cpp
  signal_handler_tests.cpp
  daemon_tests.cpp
  session_table_tests.cpp
  advanced_rate_limiter_tests.cpp
  session_lifecycle_tests.cpp
  constrained_logging_tests.cpp
  metrics_tests.cpp
  session_migration_tests.cpp
)

target_link_libraries(veil_unit_tests PRIVATE
  veil_common
  GTest::gtest_main
)

veil_set_warnings(veil_unit_tests)

include(GoogleTest)
gtest_discover_tests(veil_unit_tests PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
