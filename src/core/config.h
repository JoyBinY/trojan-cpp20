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

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <boost/property_tree/ptree.hpp>
#include "log.h"

class Config {
public:
    enum class RunType {
        SERVER,
        CLIENT,
        FORWARD,
        NAT
    } run_type;
    std::string local_addr;
    uint16_t local_port = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    std::string target_addr;
    uint16_t target_port = 0;
    std::map<std::string, std::string> password;
    int udp_timeout = 60;
    Log::Level log_level = Log::Level::INFO;
    struct SSLConfig {
        bool verify = true;
        bool verify_hostname = true;
        std::string cert;
        std::string key;
        std::string key_password;
        std::string cipher;
        std::string cipher_tls13;
        bool prefer_server_cipher = true;
        std::string sni;
        std::string alpn;
        std::map<std::string, uint16_t> alpn_port_override;
        bool reuse_session = true;
        bool session_ticket = false;
        long session_timeout = 600;
        std::string plain_http_response;
        std::string curves;
        std::string dhparam;
    } ssl;
    struct TCPConfig {
        bool prefer_ipv4 = false;
        bool no_delay = true;
        bool keep_alive = true;
        bool reuse_port = false;
        bool fast_open = false;
        int fast_open_qlen = 20;
    } tcp;
    struct MySQLConfig {
        bool enabled = false;
        std::string server_addr;
        uint16_t server_port = 3306;
        std::string database;
        std::string username;
        std::string password;
        std::string key;
        std::string cert;
        std::string ca;
    } mysql;
    void load(std::string_view filename);
    void populate(std::string_view JSON);
    bool sip003();
    [[nodiscard]] static std::string SHA224(std::string_view message);
private:
    void populate(const boost::property_tree::ptree &tree);
};
