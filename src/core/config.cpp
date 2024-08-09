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
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <sstream>
#include <stdexcept>

using namespace std;
using namespace rapidjson;

void Config::load(const string &filename) {
  const auto &path = filesystem::canonical(filename);
  ifstream ifs(path.string(), ios_base::in);
  if (ifs.is_open()) {
    IStreamWrapper isw(ifs);

    Document tree;
    tree.ParseStream(isw);
    populate(tree);
  }
}

void Config::populate(const string &JSON) {
  istringstream s(JSON);
  IStreamWrapper isw(s);

  Document tree;
  tree.ParseStream(isw);
  populate(tree);
}

void Config::populate(const Document &tree) {
  string rt = get_json_value(tree, "run_type", "client");
  if (rt == "server") {
    run_type = SERVER;
  } else if (rt == "forward") {
    run_type = FORWARD;
  } else if (rt == "nat") {
    run_type = NAT;
  } else if (rt == "client") {
    run_type = CLIENT;
  } else {
    throw runtime_error("wrong run_type in config file");
  }
  local_addr = get_json_value(tree, "local_addr", string());
  local_port = get_json_value(tree, "local_port", uint16_t());
  remote_addr = get_json_value(tree, "remote_addr", string());
  remote_port = get_json_value(tree, "remote_port", uint16_t());
  target_addr = get_json_value(tree, "target_addr", string());
  target_port = get_json_value(tree, "target_port", uint16_t());
  map<string, string>().swap(password);
  if (tree.HasMember("password") && tree["password"].IsArray()) {
    for (auto &item : tree["password"].GetArray()) {
      string p = item.GetString();
      password[SHA224(p)] = p;
    }
  }
  udp_timeout = get_json_value(tree, "udp_timeout", 60);
  log_level = static_cast<Log::Level>(get_json_value(tree, "log_level", 1));

  if (tree.HasMember("ssl") && tree["ssl"].IsObject()) {
    const auto &node = tree["ssl"];
    ssl.verify = get_json_value(node, "verify", true);
    ssl.verify_hostname = get_json_value(node, "verify_hostname", true);
    ssl.cert = get_json_value(node, "cert", string());
    ssl.key = get_json_value(node, "key", string());
    ssl.key_password = get_json_value(node, "key_password", string());
    ssl.cipher = get_json_value(node, "cipher", string());
    ssl.cipher_tls13 = get_json_value(node, "cipher_tls13", string());
    ssl.prefer_server_cipher =
        get_json_value(node, "prefer_server_cipher", true);
    ssl.sni = get_json_value(node, "sni", string());
    ssl.alpn = "";
    if (node.HasMember("alpn")) {
      for (auto &item : node["alpn"].GetArray()) {
        string proto = item.GetString();
        ssl.alpn += (char)((unsigned char)(proto.length()));
        ssl.alpn += proto;
      }
    }
    map<string, uint16_t>().swap(ssl.alpn_port_override);
    if (node.HasMember("alpn_port_override") &&
        node["alpn_port_override"].IsArray()) {
      for (Value::ConstMemberIterator itr =
               node["alpn_port_override"].MemberBegin();
           itr != node.MemberEnd(); ++itr)
        ssl.alpn_port_override[itr->name.GetString()] = itr->value.GetUint();
    }

    ssl.reuse_session = get_json_value(node, "reuse_session", true);
    ssl.session_ticket = get_json_value(node, "session_ticket", false);
    ssl.session_timeout = get_json_value(node, "session_timeout", long(600));
    ssl.plain_http_response =
        get_json_value(node, "plain_http_response", string());
    ssl.curves = get_json_value(node, "curves", string());
    ssl.dhparam = get_json_value(node, "dhparam", string());
  }
  if (tree.HasMember("tcp") && tree["tcp"].IsObject()) {
    const auto &node = tree["tcp"];
    tcp.prefer_ipv4 = get_json_value(node, "tcp.prefer_ipv4", false);
    tcp.no_delay = get_json_value(node, "no_delay", true);
    tcp.keep_alive = get_json_value(node, "keep_alive", true);
    tcp.reuse_port = get_json_value(node, "reuse_port", false);
    tcp.fast_open = get_json_value(node, "fast_open", false);
    tcp.fast_open_qlen = get_json_value(node, "fast_open_qlen", 20);
  }
  if (tree.HasMember("mysql") && tree["mysql"].IsObject()) {
    const auto &node = tree["mysql"];
    mysql.enabled = get_json_value(node, "enabled", false);
    mysql.server_addr =
        get_json_value(node, "server_addr", string("127.0.0.1"));
    mysql.server_port = get_json_value(node, "server_port", uint16_t(3306));
    mysql.database = get_json_value(node, "database", string("trojan"));
    mysql.username = get_json_value(node, "username", string("trojan"));
    mysql.password = get_json_value(node, "password", string());
    mysql.key = get_json_value(node, "key", string());
    mysql.cert = get_json_value(node, "cert", string());
    mysql.ca = get_json_value(node, "ca", string());    
  }
}

bool Config::sip003() {
  char *JSON = getenv("SS_PLUGIN_OPTIONS");
  if (JSON == nullptr) {
    return false;
  }
  populate(JSON);
  switch (run_type) {
  case SERVER:
    local_addr = getenv("SS_REMOTE_HOST");
    local_port = atoi(getenv("SS_REMOTE_PORT"));
    break;
  case CLIENT:
  case NAT:
    throw runtime_error("SIP003 with wrong run_type");
  case FORWARD:
    remote_addr = getenv("SS_REMOTE_HOST");
    remote_port = atoi(getenv("SS_REMOTE_PORT"));
    local_addr = getenv("SS_LOCAL_HOST");
    local_port = atoi(getenv("SS_LOCAL_PORT"));
    break;
  }
  return true;
}

string Config::SHA224(const string &message) {
  uint8_t digest[EVP_MAX_MD_SIZE];
  char mdString[(EVP_MAX_MD_SIZE << 1) + 1];
  unsigned int digest_len;
  EVP_MD_CTX *ctx;
  if ((ctx = EVP_MD_CTX_new()) == nullptr) {
    throw runtime_error("could not create hash context");
  }
  if (!EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr)) {
    EVP_MD_CTX_free(ctx);
    throw runtime_error("could not initialize hash context");
  }
  if (!EVP_DigestUpdate(ctx, message.c_str(), message.length())) {
    EVP_MD_CTX_free(ctx);
    throw runtime_error("could not update hash");
  }
  if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
    EVP_MD_CTX_free(ctx);
    throw runtime_error("could not output hash");
  }

  for (unsigned int i = 0; i < digest_len; ++i) {
    sprintf(mdString + (i << 1), "%02x", (unsigned int)digest[i]);
  }
  mdString[digest_len << 1] = '\0';
  EVP_MD_CTX_free(ctx);
  return string(mdString);
}
