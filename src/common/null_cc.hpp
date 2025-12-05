// null_cc.hpp
// Null congestion controller: no control, allow pacer to use requested rate.
#pragma once

#include <cstdint>

class null_congestion_controller {
public:
    null_congestion_controller() = default;
    void set_initial_rate(double) {}
    void on_send(uint64_t, uint64_t) {}
    void on_ack(uint64_t, uint64_t, uint64_t) {}
    void on_poll(uint64_t) {}
    double target_rate_pps() const { return 0.0; }
};
