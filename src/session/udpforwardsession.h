/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "session.h"
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>

class UDPForwardSession : public Session {
public:
    typedef std::function<void(const asio::ip::udp::endpoint&, const std::string&)> UDPWrite;
private:
    enum Status {
        CONNECT,
        FORWARD,
        FORWARDING,
        DESTROY
    } status;
    UDPWrite in_write;
    asio::ssl::stream<asio::ip::tcp::socket>out_socket;
    asio::steady_timer gc_timer;
    void destroy();
    void in_recv(const std::string &data);
    void out_async_read();
    void out_async_write(const std::string &data);
    void out_recv(const std::string &data);
    void out_sent();
    void timer_async_wait();
public:
    UDPForwardSession(const Config &config, asio::io_context &io_context, asio::ssl::context &ssl_context, const asio::ip::udp::endpoint &endpoint, UDPWrite in_write);
    asio::ip::tcp::socket& accept_socket() override;
    void start() override;
    bool process(const asio::ip::udp::endpoint &endpoint, const std::string &data);
};