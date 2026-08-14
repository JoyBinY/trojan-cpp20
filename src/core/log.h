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

#include <cstdio>
#include <string_view>
#include <asio/ip/tcp.hpp>

#ifdef ERROR // windows.h
#undef ERROR
#endif // ERROR

class Log {
public:
    enum class Level : int {
        ALL = 0,
        INFO = 1,
        WARN = 2,
        ERROR = 3,
        FATAL = 4,
        OFF = 5
    };
    static Level level;
    static FILE *keylog;
    static void log(std::string_view message, Level level = Level::ALL);
    static void log_with_date_time(std::string_view message, Level level = Level::ALL);
    static void log_with_endpoint(const asio::ip::tcp::endpoint &endpoint, std::string_view message, Level level = Level::ALL);
    static void redirect(std::string_view filename);
    static void redirect_keylog(std::string_view filename);
    static void reset();
private:
    static FILE *output_stream;
};
