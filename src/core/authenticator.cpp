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

#include "authenticator.h"
#include <cstdlib>
#include <stdexcept>
#include <string>
using namespace std;

#ifdef ENABLE_MYSQL

Authenticator::Authenticator(const Config &config) {
    mysql_init(&con);
    Log::log_with_date_time("connecting to MySQL server " + config.mysql.server_addr + ':' + to_string(config.mysql.server_port), Log::Level::INFO);
    if (!config.mysql.ca.empty()) {
        if (!config.mysql.key.empty() && !config.mysql.cert.empty()) {
            mysql_ssl_set(&con, config.mysql.key.c_str(), config.mysql.cert.c_str(), config.mysql.ca.c_str(), nullptr, nullptr);
        } else {
            mysql_ssl_set(&con, nullptr, nullptr, config.mysql.ca.c_str(), nullptr, nullptr);
        }
    }
    if (mysql_real_connect(&con, config.mysql.server_addr.c_str(),
                                 config.mysql.username.c_str(),
                                 config.mysql.password.c_str(),
                                 config.mysql.database.c_str(),
                                 config.mysql.server_port, nullptr, 0) == nullptr) {
        throw runtime_error(mysql_error(&con));
    }
    bool reconnect = true;
    mysql_options(&con, MYSQL_OPT_RECONNECT, &reconnect);
    Log::log_with_date_time("connected to MySQL server", Log::Level::INFO);
}

bool Authenticator::auth(string_view password) {
    if (!is_valid_password(password)) {
        return false;
    }
    string pw(password);
    if (mysql_query(&con, ("SELECT quota, download + upload FROM users WHERE password = '" + pw + '\'').c_str())) {
        Log::log_with_date_time(mysql_error(&con), Log::Level::ERROR);
        return false;
    }
    MYSQL_RES *res = mysql_store_result(&con);
    if (res == nullptr) {
        Log::log_with_date_time(mysql_error(&con), Log::Level::ERROR);
        return false;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row == nullptr) {
        mysql_free_result(res);
        return false;
    }
    int64_t quota = atoll(row[0]);
    int64_t used = atoll(row[1]);
    mysql_free_result(res);
    if (quota < 0) {
        return true;
    }
    if (used >= quota) {
        Log::log_with_date_time(pw + " ran out of quota", Log::Level::WARN);
        return false;
    }
    return true;
}

void Authenticator::record(string_view password, uint64_t download, uint64_t upload) {
    if (!is_valid_password(password)) {
        return;
    }
    string pw(password);
    if (mysql_query(&con, ("UPDATE users SET download = download + " + to_string(download) + ", upload = upload + " + to_string(upload) + " WHERE password = '" + pw + '\'').c_str())) {
        Log::log_with_date_time(mysql_error(&con), Log::Level::ERROR);
    }
}

bool Authenticator::is_valid_password(string_view password) {
    if (password.size() != PASSWORD_LENGTH) {
        return false;
    }
    for (char c : password) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

Authenticator::~Authenticator() {
    mysql_close(&con);
}

#else // ENABLE_MYSQL

Authenticator::Authenticator(const Config&) {}
bool Authenticator::auth(string_view) { return true; }
void Authenticator::record(string_view, uint64_t, uint64_t) {}
bool Authenticator::is_valid_password(string_view) { return true; }
Authenticator::~Authenticator() {}

#endif // ENABLE_MYSQL
