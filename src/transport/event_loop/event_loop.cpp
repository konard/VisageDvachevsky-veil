#include "transport/event_loop/event_loop.h"

#include <sys/epoll.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include "common/logging/logger.h"

namespace veil::transport {

EventLoop::EventLoop(EventLoopConfig config, std::function<TimePoint()> now_fn)
    : config_(config), now_fn_(std::move(now_fn)), timer_heap_(now_fn_) {
  epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd_ < 0) {
    LOG_ERROR("Failed to create epoll fd: {}", std::error_code(errno, std::generic_category()).message());
  }
}

EventLoop::~EventLoop() {
  stop();
  if (epoll_fd_ >= 0) {
    ::close(epoll_fd_);
    epoll_fd_ = -1;
  }
}

bool EventLoop::add_socket(UdpSocket* socket, SessionId session_id, const UdpEndpoint& remote,
                           PacketHandler on_packet, TimerHandler on_ack_timeout,
                           TimerHandler on_retransmit, TimerHandler on_idle_timeout,
                           ErrorHandler on_error) {
  VEIL_DCHECK_THREAD(thread_checker_);

  if (socket == nullptr || epoll_fd_ < 0) {
    return false;
  }

  const int fd = socket->fd();
  if (fd < 0) {
    return false;
  }

  // Check if already registered.
  if (sockets_.find(fd) != sockets_.end()) {
    LOG_WARN("Socket fd={} already registered", fd);
    return false;
  }

  // Add to epoll (level-triggered for reads, edge-triggered for writes).
  epoll_event ev{};
  ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
  ev.data.fd = fd;
  if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) != 0) {
    LOG_ERROR("epoll_ctl ADD failed for fd={}: {}", fd,
              std::error_code(errno, std::generic_category()).message());
    return false;
  }

  // Create socket info.
  SocketInfo info{};
  info.socket = socket;
  info.session_id = session_id;
  info.remote = remote;
  info.on_packet = std::move(on_packet);
  info.on_ack_timeout = std::move(on_ack_timeout);
  info.on_retransmit = std::move(on_retransmit);
  info.on_idle_timeout = std::move(on_idle_timeout);
  info.on_error = std::move(on_error);
  info.last_activity = now_fn_();
  info.writable = true;

  sockets_[fd] = std::move(info);

  // Setup session timers.
  setup_session_timers(sockets_[fd]);

  LOG_DEBUG("Added socket fd={} for session={}", fd, session_id);
  return true;
}

bool EventLoop::remove_socket(int fd) {
  VEIL_DCHECK_THREAD(thread_checker_);

  auto it = sockets_.find(fd);
  if (it == sockets_.end()) {
    return false;
  }

  // Cleanup timers.
  cleanup_session_timers(it->second);

  // Remove from epoll.
  if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) != 0) {
    LOG_WARN("epoll_ctl DEL failed for fd={}: {}", fd,
             std::error_code(errno, std::generic_category()).message());
  }

  sockets_.erase(it);
  LOG_DEBUG("Removed socket fd={}", fd);
  return true;
}

bool EventLoop::send_packet(int fd, std::span<const std::uint8_t> data, const UdpEndpoint& remote) {
  VEIL_DCHECK_THREAD(thread_checker_);

  auto it = sockets_.find(fd);
  if (it == sockets_.end()) {
    return false;
  }

  auto& info = it->second;

  // If socket is writable and no pending sends, try immediate send.
  if (info.writable && info.pending_sends.empty()) {
    std::error_code ec;
    if (info.socket->send(data, remote, ec)) {
      return true;
    }
    // If would block, queue it.
    if (ec.value() == EAGAIN || ec.value() == EWOULDBLOCK) {
      info.writable = false;
    } else {
      LOG_ERROR("Send failed for fd={}: {}", fd, ec.message());
      if (info.on_error) {
        info.on_error(info.session_id, ec);
      }
      return false;
    }
  }

  // Queue the packet.
  info.pending_sends.push_back(
      UdpPacket{std::vector<std::uint8_t>(data.begin(), data.end()), remote});
  return true;
}

utils::TimerId EventLoop::schedule_timer(std::chrono::steady_clock::duration after,
                                         utils::TimerCallback callback) {
  VEIL_DCHECK_THREAD(thread_checker_);
  return timer_heap_.schedule_after(after, std::move(callback));
}

bool EventLoop::cancel_timer(utils::TimerId id) {
  VEIL_DCHECK_THREAD(thread_checker_);
  return timer_heap_.cancel(id);
}

void EventLoop::reset_idle_timeout(int fd) {
  VEIL_DCHECK_THREAD(thread_checker_);

  auto it = sockets_.find(fd);
  if (it == sockets_.end()) {
    return;
  }

  auto& info = it->second;
  info.last_activity = now_fn_();

  // Reschedule idle timer.
  if (info.idle_timer_id != utils::kInvalidTimerId) {
    timer_heap_.reschedule_after(info.idle_timer_id, config_.idle_timeout);
  }
}

void EventLoop::run() {
  if (epoll_fd_ < 0) {
    LOG_ERROR("Cannot run event loop: invalid epoll fd");
    return;
  }

  // Bind thread checker to the current thread (the event loop thread).
  // All subsequent operations on this EventLoop must happen on this thread.
  thread_checker_.rebind_to_current();

  running_.store(true);
  LOG_INFO("Event loop started");

  std::vector<epoll_event> events(static_cast<std::size_t>(config_.max_events));

  while (running_.load()) {
    // Calculate timeout based on next timer.
    int timeout_ms = config_.epoll_timeout_ms;
    auto next_timer = timer_heap_.time_until_next();
    if (next_timer) {
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(*next_timer).count();
      if (ms < 0) ms = 0;
      timeout_ms = std::min(timeout_ms, static_cast<int>(ms));
    }

    const int n = epoll_wait(epoll_fd_, events.data(), config_.max_events, timeout_ms);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      LOG_ERROR("epoll_wait failed: {}", std::error_code(errno, std::generic_category()).message());
      break;
    }

    // Process I/O events.
    for (int i = 0; i < n; ++i) {
      const auto& ev = events[static_cast<std::size_t>(i)];
      const int fd = ev.data.fd;

      if ((ev.events & EPOLLIN) != 0U) {
        handle_read(fd);
      }
      if ((ev.events & EPOLLOUT) != 0U) {
        handle_write(fd);
      }
      if ((ev.events & (EPOLLERR | EPOLLHUP)) != 0U) {
        auto it = sockets_.find(fd);
        if (it != sockets_.end() && it->second.on_error) {
          it->second.on_error(it->second.session_id,
                              std::make_error_code(std::errc::connection_reset));
        }
      }
    }

    // Process expired timers.
    handle_timers();
  }

  LOG_INFO("Event loop stopped");
}

void EventLoop::stop() { running_.store(false); }

void EventLoop::handle_read(int fd) {
  auto it = sockets_.find(fd);
  if (it == sockets_.end()) {
    return;
  }

  auto& info = it->second;

  // Read packets in a loop (edge-triggered, must drain).
  while (true) {
    std::error_code ec;
    bool got_packet = false;

    info.socket->poll(
        [&](const UdpPacket& pkt) {
          got_packet = true;
          info.last_activity = now_fn_();

          if (info.on_packet) {
            info.on_packet(info.session_id, pkt.data, pkt.remote);
          }
        },
        0, ec);

    if (!got_packet) {
      break;
    }
  }
}

void EventLoop::handle_write(int fd) {
  auto it = sockets_.find(fd);
  if (it == sockets_.end()) {
    return;
  }

  auto& info = it->second;
  info.writable = true;

  // Send pending packets.
  while (!info.pending_sends.empty()) {
    auto& pkt = info.pending_sends.front();
    std::error_code ec;
    if (!info.socket->send(pkt.data, pkt.remote, ec)) {
      if (ec.value() == EAGAIN || ec.value() == EWOULDBLOCK) {
        info.writable = false;
        break;
      }
      LOG_ERROR("Send failed for fd={}: {}", fd, ec.message());
      if (info.on_error) {
        info.on_error(info.session_id, ec);
      }
      break;
    }
    info.pending_sends.erase(info.pending_sends.begin());
  }
}

void EventLoop::handle_timers() { timer_heap_.process_expired(); }

void EventLoop::setup_session_timers(SocketInfo& info) {
  const SessionId session_id = info.session_id;

  // ACK timeout timer.
  if (info.on_ack_timeout) {
    info.ack_timer_id = timer_heap_.schedule_after(config_.ack_interval, [this, session_id](utils::TimerId) {
      for (auto& [fd, socket_info] : sockets_) {
        if (socket_info.session_id == session_id && socket_info.on_ack_timeout) {
          socket_info.on_ack_timeout(session_id);
          // Reschedule.
          socket_info.ack_timer_id =
              timer_heap_.schedule_after(config_.ack_interval, [this, session_id](utils::TimerId) {
                // Recursive lambda via capture.
                for (auto& [inner_fd, inner_info] : sockets_) {
                  if (inner_info.session_id == session_id && inner_info.on_ack_timeout) {
                    inner_info.on_ack_timeout(session_id);
                  }
                }
              });
          break;
        }
      }
    });
  }

  // Retransmit timer.
  if (info.on_retransmit) {
    info.retransmit_timer_id =
        timer_heap_.schedule_after(config_.retransmit_interval, [this, session_id](utils::TimerId) {
          for (auto& [fd, socket_info] : sockets_) {
            if (socket_info.session_id == session_id && socket_info.on_retransmit) {
              socket_info.on_retransmit(session_id);
              // Reschedule.
              socket_info.retransmit_timer_id = timer_heap_.schedule_after(
                  config_.retransmit_interval, [this, session_id](utils::TimerId) {
                    for (auto& [inner_fd, inner_info] : sockets_) {
                      if (inner_info.session_id == session_id && inner_info.on_retransmit) {
                        inner_info.on_retransmit(session_id);
                      }
                    }
                  });
              break;
            }
          }
        });
  }

  // Idle timeout timer.
  if (info.on_idle_timeout) {
    info.idle_timer_id =
        timer_heap_.schedule_after(config_.idle_timeout, [this, session_id](utils::TimerId) {
          for (auto& [fd, socket_info] : sockets_) {
            if (socket_info.session_id == session_id && socket_info.on_idle_timeout) {
              socket_info.on_idle_timeout(session_id);
              break;
            }
          }
        });
  }
}

void EventLoop::cleanup_session_timers(SocketInfo& info) {
  if (info.ack_timer_id != utils::kInvalidTimerId) {
    timer_heap_.cancel(info.ack_timer_id);
    info.ack_timer_id = utils::kInvalidTimerId;
  }
  if (info.retransmit_timer_id != utils::kInvalidTimerId) {
    timer_heap_.cancel(info.retransmit_timer_id);
    info.retransmit_timer_id = utils::kInvalidTimerId;
  }
  if (info.idle_timer_id != utils::kInvalidTimerId) {
    timer_heap_.cancel(info.idle_timer_id);
    info.idle_timer_id = utils::kInvalidTimerId;
  }
}

}  // namespace veil::transport
