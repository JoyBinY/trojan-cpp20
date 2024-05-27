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

class ForwardSession : public Session {
private:
    enum Status {
        CONNECT,
        FORWARD,
        DESTROY
    } status;
    bool first_packet_recv;
    asio::ip::tcp::socket in_socket;
    asio::ssl::stream<asio::ip::tcp::socket>out_socket;
    void destroy();
    void in_async_read();
    void in_async_write(const std::string &data);
    void in_recv(const std::string &data);
    void in_sent();
    void out_async_read();
    void out_async_write(const std::string &data);
    void out_recv(const std::string &data);
    void out_sent();
public:
    ForwardSession(const Config &config, asio::io_context &io_context, asio::ssl::context &ssl_context);
    asio::ip::tcp::socket& accept_socket() override;
    void start() override;
};