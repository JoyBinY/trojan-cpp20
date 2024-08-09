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

#include <asio/signal_set.hpp>
#include <cstdlib>
#include <cxxopts.hpp>
#include <format>
#include <iostream>
#include <openssl/opensslv.h>
#ifdef ENABLE_MYSQL
#include <mysql.h>
#endif // ENABLE_MYSQL
#include "core/service.h"
#include "core/version.h"
using namespace std;

#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG "config.json"
#endif // DEFAULT_CONFIG

//macro to string
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

void signal_async_wait(asio::signal_set &sig, Service &service, bool &restart) {
  sig.async_wait([&](const asio::error_code error, int signum) {
    if (error) {
      return;
    }
    Log::log_with_date_time("got signal: " + to_string(signum), Log::WARN);
    switch (signum) {
    case SIGINT:
    case SIGTERM:
      service.stop();
      break;
#ifndef _WIN32
    case SIGHUP:
      restart = true;
      service.stop();
      break;
    case SIGUSR1:
      service.reload_cert();
      signal_async_wait(sig, service, restart);
      break;
#endif // _WIN32
    }
  });
}

int main(int argc, const char *argv[]) {
  try {
    Log::log("Welcome to trojan " + Version::get_version(), Log::FATAL);
    string config_file;
    string log_file;
    string keylog_file;
    cxxopts::Options desc(string(argv[0]), {});
    desc.allow_unrecognised_options().add_options({})
      ("config,c", "specify config file", cxxopts::value(config_file)->default_value(DEFAULT_CONFIG), "CONFIG")
      ("help,h", "print help message")
      ("keylog,k", "specify keylog file location (OpenSSL >= 1.1.1)", cxxopts::value(keylog_file), "KEYLOG")
      ("log,l", "specify log file location", cxxopts::value(log_file), "LOG")
      ("test,t", "test config file")
      ("version,v", "print version and build info");
    desc.parse_positional("config");
    desc.positional_help("[config]").show_positional_help();
    auto vm = desc.parse(argc, argv);
    if (vm.count("help")) {
      desc.custom_help("[-htv] [-l LOG] [-k KEYLOG] [[-c] CONFIG]");
      std::cerr << desc.help();
      exit(EXIT_SUCCESS);
    }
    if (vm.count("version")) {
      Log::log(std::format("asio {}, cxxopts {}, RapidJSON {}", TOSTRING(ASIO_VERSION), TOSTRING(CXXOPTS_VERSION), TOSTRING(RAPIDJSON_VERSION)), Log::FATAL);
#ifdef ENABLE_MYSQL
      Log::log(" [Enabled] MySQL Support ("s + mysql_get_client_info() + ')',
               Log::FATAL);
#else  // ENABLE_MYSQL
      Log::log("[Disabled] MySQL Support", Log::FATAL);
#endif // ENABLE_MYSQL
#ifdef TCP_FASTOPEN
      Log::log(" [Enabled] TCP_FASTOPEN Support", Log::FATAL);
#else  // TCP_FASTOPEN
      Log::log("[Disabled] TCP_FASTOPEN Support", Log::FATAL);
#endif // TCP_FASTOPEN
#ifdef TCP_FASTOPEN_CONNECT
      Log::log(" [Enabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#else  // TCP_FASTOPEN_CONNECT
      Log::log("[Disabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#endif // TCP_FASTOPEN_CONNECT
#if ENABLE_SSL_KEYLOG
      Log::log(" [Enabled] SSL KeyLog Support", Log::FATAL);
#else  // ENABLE_SSL_KEYLOG
      Log::log("[Disabled] SSL KeyLog Support", Log::FATAL);
#endif // ENABLE_SSL_KEYLOG
#ifdef ENABLE_NAT
      Log::log(" [Enabled] NAT Support", Log::FATAL);
#else  // ENABLE_NAT
      Log::log("[Disabled] NAT Support", Log::FATAL);
#endif // ENABLE_NAT
#ifdef ENABLE_TLS13_CIPHERSUITES
      Log::log(" [Enabled] TLS1.3 Ciphersuites Support", Log::FATAL);
#else  // ENABLE_TLS13_CIPHERSUITES
      Log::log("[Disabled] TLS1.3 Ciphersuites Support", Log::FATAL);
#endif // ENABLE_TLS13_CIPHERSUITES
#ifdef ENABLE_REUSE_PORT
      Log::log(" [Enabled] TCP Port Reuse Support", Log::FATAL);
#else  // ENABLE_REUSE_PORT
      Log::log("[Disabled] TCP Port Reuse Support", Log::FATAL);
#endif // ENABLE_REUSE_PORT
      Log::log("OpenSSL Information", Log::FATAL);
      if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) {
        Log::log("\tCompile-time Version: "s + OPENSSL_VERSION_TEXT, Log::FATAL);
      }
      Log::log("\tBuild Flags: "s + OpenSSL_version(OPENSSL_CFLAGS),
               Log::FATAL);
      exit(EXIT_SUCCESS);
    }
    if (vm.count("log")) {
      Log::redirect(log_file);
    }
    if (vm.count("keylog")) {
      Log::redirect_keylog(keylog_file);
    }
    bool restart;
    Config config;
    do {
      restart = false;
      if (config.sip003()) {
        Log::log_with_date_time("SIP003 is loaded", Log::WARN);
      } else {
        config.load(config_file);
      }
      bool test = vm.count("test");
      Service service(config, test);
      if (test) {
        Log::log("The config file looks good.", Log::OFF);
        exit(EXIT_SUCCESS);
      }
      asio::signal_set sig(service.service());
      sig.add(SIGINT);
      sig.add(SIGTERM);
#ifndef _WIN32
      sig.add(SIGHUP);
      sig.add(SIGUSR1);
#endif // _WIN32
      signal_async_wait(sig, service, restart);
      service.run();
      if (restart) {
        Log::log_with_date_time("trojan service restarting. . . ", Log::WARN);
      }
    } while (restart);
    Log::reset();
    exit(EXIT_SUCCESS);
  } catch (const exception &e) {
    Log::log_with_date_time("fatal: "s + e.what(), Log::FATAL);
    Log::log_with_date_time("exiting. . . ", Log::FATAL);
    exit(EXIT_FAILURE);
  }
}