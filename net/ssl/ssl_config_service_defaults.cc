// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_config_service_defaults.h"

namespace net {

SSLConfigServiceDefaults::SSLConfigServiceDefaults() = default;
SSLConfigServiceDefaults::~SSLConfigServiceDefaults() = default;

SSLConfigServiceDefaults::SSLConfigServiceDefaults(SSLContextConfig default_config): default_config_(default_config) {
  // default_config.disabled_cipher_suites = default_config_.disabled_cipher_suites;
}

SSLContextConfig SSLConfigServiceDefaults::GetSSLContextConfig() {
  return default_config_;
}

bool SSLConfigServiceDefaults::CanShareConnectionWithClientCerts(
    std::string_view hostname) const {
  return false;
}

}  // namespace net
