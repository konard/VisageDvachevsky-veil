add_library(veil_common STATIC
  common/crypto/random.cpp
  common/crypto/crypto_engine.cpp
  common/logging/logger.cpp
  common/logging/constrained_logger.cpp
  common/config/app_config.cpp
  common/packet/packet_builder.cpp
  common/session/replay_window.cpp
  common/session/session_rotator.cpp
  common/session/session_lifecycle.cpp
  common/session/idle_timeout.cpp
  common/handshake/handshake_processor.cpp
  common/handshake/handshake_replay_cache.cpp
  common/utils/rate_limiter.cpp
  common/utils/timer_heap.cpp
  common/utils/advanced_rate_limiter.cpp
  common/utils/graceful_degradation.cpp
  common/metrics/metrics.cpp
  common/obfuscation/obfuscation_profile.cpp
  common/protocol_wrapper/websocket_wrapper.cpp
  common/signal/signal_handler.cpp
  common/daemon/daemon.cpp
  common/ipc/ipc_protocol.cpp
  common/ipc/ipc_socket.cpp
  transport/udp_socket/udp_socket.cpp
  transport/mux/ack_bitmap.cpp
  transport/mux/reorder_buffer.cpp
  transport/mux/fragment_reassembly.cpp
  transport/mux/mux_codec.cpp
  transport/mux/retransmit_buffer.cpp
  transport/mux/ack_scheduler.cpp
  transport/session/transport_session.cpp
  transport/event_loop/event_loop.cpp
  transport/stats/transport_stats.cpp
  tun/tun_device.cpp
  tun/routing.cpp
  tun/mtu_discovery.cpp
  tunnel/tunnel.cpp
  tunnel/session_migration.cpp
  server/session_table.cpp
)

target_include_directories(veil_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(veil_common
  PUBLIC
    Sodium::Sodium
    spdlog::spdlog
    fmt::fmt
    CLI11::CLI11
    nlohmann_json::nlohmann_json
)

veil_set_warnings(veil_common)

if(TARGET sodium_ep)
  add_dependencies(veil_common sodium_ep)
endif()

# Client executable.
add_executable(veil-client
  client/main.cpp
  client/client_config.cpp
)

target_link_libraries(veil-client PRIVATE veil_common)
veil_set_warnings(veil-client)

install(TARGETS veil-client
  RUNTIME DESTINATION bin
)

# Server executable (optional).
option(VEIL_BUILD_SERVER "Build server executable" ON)

if(VEIL_BUILD_SERVER)
  add_executable(veil-server
    server/main.cpp
    server/server_config.cpp
  )

  target_link_libraries(veil-server PRIVATE veil_common)
  veil_set_warnings(veil-server)

  install(TARGETS veil-server
    RUNTIME DESTINATION bin
  )
endif()

# GUI applications (optional, require Qt6)
option(VEIL_BUILD_GUI "Build Qt GUI applications" ON)

if(VEIL_BUILD_GUI)
  add_subdirectory(gui-client)
  if(VEIL_BUILD_SERVER)
    add_subdirectory(gui-server)
  endif()
endif()
