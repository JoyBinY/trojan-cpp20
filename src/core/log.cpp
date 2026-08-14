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

#include "log.h"
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <sstream>
#include <array>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#ifdef ENABLE_ANDROID_LOG
#include <android/log.h>
#endif // ENABLE_ANDROID_LOG
using namespace std;
using namespace boost::posix_time;
using namespace boost::asio::ip;

Log::Level Log::level(Log::Level::INFO);
FILE *Log::keylog = nullptr;
FILE *Log::output_stream = stderr;
Log::LogCallback Log::log_callback{};

void Log::log(string_view message, Level level) {
    if (level >= Log::level) {
#ifdef ENABLE_ANDROID_LOG
        __android_log_print(ANDROID_LOG_ERROR, "trojan", "%s\n",
                            string(message).c_str());
#else
        fprintf(output_stream, "%.*s\n", static_cast<int>(message.size()), message.data());
        fflush(output_stream);
#endif // ENABLE_ANDROID_LOG
        if (log_callback) {
            log_callback(string(message), level);
        }
    }
}

void Log::log_with_date_time(string_view message, Level level) {
    static constexpr array<const char*, 6> level_strings = {"ALL", "INFO", "WARN", "ERROR", "FATAL", "OFF"};
    auto *facet = new time_facet("[%Y-%m-%d %H:%M:%S] ");
    ostringstream stream;
    stream.imbue(locale(stream.getloc(), facet));
    stream << second_clock::local_time();
    string level_string = '[' + string(level_strings[static_cast<int>(level)]) + "] ";
    log(stream.str() + level_string + string(message), level);
}

void Log::log_with_endpoint(const tcp::endpoint &endpoint, string_view message, Level level) {
    log_with_date_time(endpoint.address().to_string() + ':' + to_string(endpoint.port()) + ' ' + string(message), level);
}

void Log::redirect(string_view filename) {
    string fn(filename);
    FILE *fp = fopen(fn.c_str(), "a");
    if (fp == nullptr) {
        throw runtime_error(string(filename) + ": " + strerror(errno));
    }
    if (output_stream != stderr) {
        fclose(output_stream);
    }
    output_stream = fp;
}

void Log::redirect_keylog(string_view filename) {
    string fn(filename);
    FILE *fp = fopen(fn.c_str(), "a");
    if (fp == nullptr) {
        throw runtime_error(string(filename) + ": " + strerror(errno));
    }
    if (keylog != nullptr) {
        fclose(keylog);
    }
    keylog = fp;
}

void Log::set_callback(LogCallback cb) {
    log_callback = move(cb);
}

void Log::reset() {
    if (output_stream != stderr) {
        fclose(output_stream);
        output_stream = stderr;
    }
    if (keylog != nullptr) {
        fclose(keylog);
        keylog = nullptr;
    }
}
