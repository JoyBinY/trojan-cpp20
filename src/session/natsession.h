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

#include <string>
#include <string_view>
#include <utility>
#include <asio/ssl.hpp>
#include "session.h"

class NATSession : public Session {
private:
    enum class Status {
        CONNECT,
        FORWARD,
        DESTROY
    } status;
    bool first_packet_recv = false;
    asio::ip::tcp::socket in_socket;
    asio::ssl::stream<asio::ip::tcp::socket> out_socket;
    void destroy();
    void in_async_read();
    void in_async_write(std::string_view data);
    void in_recv(std::string_view data);
    void in_sent();
    void out_async_read();
    void out_async_write(std::string_view data);
    void out_recv(std::string_view data);
    void out_sent();
    [[nodiscard]] std::pair<std::string, uint16_t> get_target_endpoint();
public:
    NATSession(const Config &config, asio::io_context &io_context, asio::ssl::context &ssl_context);
    asio::ip::tcp::socket& accept_socket() override;
    void start() override;
};
