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

#include "config.h"
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <array>
#include <fstream>
#include <openssl/evp.h>
using namespace std;
using namespace nlohmann;

void Config::load(string_view filename) {
    std::ifstream ifs{string(filename)};
    if (!ifs) {
        throw runtime_error(string(filename) + ": config file not found");
    }
    json tree = json::parse(ifs);
    populate(tree);
}

void Config::populate(string_view JSON) {
    json tree = json::parse(string(JSON));
    populate(tree);
}

void Config::populate(const json &tree) {
    string rt = tree.value("run_type", "client");
    if (rt == "server") {
        run_type = RunType::SERVER;
    } else if (rt == "forward") {
        run_type = RunType::FORWARD;
    } else if (rt == "nat") {
        run_type = RunType::NAT;
    } else if (rt == "client") {
        run_type = RunType::CLIENT;
    } else {
        throw runtime_error("wrong run_type in config file");
    }
    local_addr = tree.value("local_addr", string());
    local_port = tree.value("local_port", uint16_t());
    remote_addr = tree.value("remote_addr", string());
    remote_port = tree.value("remote_port", uint16_t());
    target_addr = tree.value("target_addr", string());
    target_port = tree.value("target_port", uint16_t());
    password.clear();
    if (tree.contains("password")) {
        for (const auto &item : tree["password"]) {
            string p = item.get<string>();
            password[SHA224(p)] = p;
        }
    }
    udp_timeout = tree.value("udp_timeout", 60);
    log_level = static_cast<Log::Level>(tree.value("log_level", 1));
    ssl.verify = tree.value("ssl.verify", true);
    ssl.verify_hostname = tree.value("ssl.verify_hostname", true);
    ssl.cert = tree.value("ssl.cert", string());
    ssl.key = tree.value("ssl.key", string());
    ssl.key_password = tree.value("ssl.key_password", string());
    ssl.cipher = tree.value("ssl.cipher", string());
    ssl.cipher_tls13 = tree.value("ssl.cipher_tls13", string());
    ssl.prefer_server_cipher = tree.value("ssl.prefer_server_cipher", true);
    ssl.sni = tree.value("ssl.sni", string());
    ssl.alpn = "";
    if (tree.contains("ssl") && tree["ssl"].contains("alpn")) {
        for (const auto &item : tree["ssl"]["alpn"]) {
            string proto = item.get<string>();
            ssl.alpn += static_cast<char>(static_cast<unsigned char>(proto.length()));
            ssl.alpn += proto;
        }
    }
    ssl.alpn_port_override.clear();
    if (tree.contains("ssl") && tree["ssl"].contains("alpn_port_override")) {
        for (auto &[key, val] : tree["ssl"]["alpn_port_override"].items()) {
            ssl.alpn_port_override[key] = val.get<uint16_t>();
        }
    }
    ssl.reuse_session = tree.value("ssl.reuse_session", true);
    ssl.session_ticket = tree.value("ssl.session_ticket", false);
    ssl.session_timeout = tree.value("ssl.session_timeout", long(600));
    ssl.plain_http_response = tree.value("ssl.plain_http_response", string());
    ssl.curves = tree.value("ssl.curves", string());
    ssl.dhparam = tree.value("ssl.dhparam", string());
    tcp.prefer_ipv4 = tree.value("tcp.prefer_ipv4", false);
    tcp.no_delay = tree.value("tcp.no_delay", true);
    tcp.keep_alive = tree.value("tcp.keep_alive", true);
    tcp.reuse_port = tree.value("tcp.reuse_port", false);
    tcp.fast_open = tree.value("tcp.fast_open", false);
    tcp.fast_open_qlen = tree.value("tcp.fast_open_qlen", 20);
    mysql.enabled = tree.value("mysql.enabled", false);
    mysql.server_addr = tree.value("mysql.server_addr", string("127.0.0.1"));
    mysql.server_port = tree.value("mysql.server_port", uint16_t(3306));
    mysql.database = tree.value("mysql.database", string("trojan"));
    mysql.username = tree.value("mysql.username", string("trojan"));
    mysql.password = tree.value("mysql.password", string());
    mysql.key = tree.value("mysql.key", string());
    mysql.cert = tree.value("mysql.cert", string());
    mysql.ca = tree.value("mysql.ca", string());
}

bool Config::sip003() {
    char *JSON = getenv("SS_PLUGIN_OPTIONS");
    if (JSON == nullptr) {
        return false;
    }
    populate(string_view(JSON));
    switch (run_type) {
        case RunType::SERVER:
            local_addr = getenv("SS_REMOTE_HOST");
            local_port = atoi(getenv("SS_REMOTE_PORT"));
            break;
        case RunType::CLIENT:
        case RunType::NAT:
            throw runtime_error("SIP003 with wrong run_type");
        case RunType::FORWARD:
            remote_addr = getenv("SS_REMOTE_HOST");
            remote_port = atoi(getenv("SS_REMOTE_PORT"));
            local_addr = getenv("SS_LOCAL_HOST");
            local_port = atoi(getenv("SS_LOCAL_PORT"));
            break;
    }
    return true;
}

string Config::SHA224(string_view message) {
    array<uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw runtime_error("could not create hash context");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("could not initialize hash context");
    }
    if (!EVP_DigestUpdate(ctx, message.data(), message.size())) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("could not update hash");
    }
    if (!EVP_DigestFinal_ex(ctx, digest.data(), &digest_len)) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("could not output hash");
    }

    string result;
    result.reserve(digest_len * 2);
    for (unsigned int i = 0; i < digest_len; ++i) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned int>(digest[i]));
        result += hex;
    }
    EVP_MD_CTX_free(ctx);
    return result;
}
