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
#include "core/authenticator.h"

class ServerSession : public Session {
private:
    enum Status {
        HANDSHAKE,
        FORWARD,
        UDP_FORWARD,
        DESTROY
    } status;
    asio::ssl::stream<asio::ip::tcp::socket>in_socket;
    asio::ip::tcp::socket out_socket;
    asio::ip::udp::resolver udp_resolver;
    Authenticator *auth;
    std::string auth_password;
    const std::string &plain_http_response;
    void destroy();
    void in_async_read();
    void in_async_write(const std::string &data);
    void in_recv(const std::string &data);
    void in_sent();
    void out_async_read();
    void out_async_write(const std::string &data);
    void out_recv(const std::string &data);
    void out_sent();
    void udp_async_read();
    void udp_async_write(const std::string &data, const asio::ip::udp::endpoint &endpoint);
    void udp_recv(const std::string &data, const asio::ip::udp::endpoint &endpoint);
    void udp_sent();
public:
    ServerSession(const Config &config, asio::io_context &io_context, asio::ssl::context &ssl_context, Authenticator *auth, const std::string &plain_http_response);
    asio::ip::tcp::socket& accept_socket() override;
    void start() override;
};