// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

#include "cronet_c.h"
#include "openssl/evp.h"
#include "sample_executor.h"
#include "sample_url_request_callback.h"
#include "third_party/boringssl/src/include/openssl/hpke.h"
#include "third_party/ohttp/ohttp.h"



// Function to base64 encode
std::string base64_encode(const std::string& input) {
    size_t output_length = 4 * ((input.size() + 2) / 3);
    std::string encoded(output_length, '\0');

    int actual_length = EVP_EncodeBlock(
      reinterpret_cast<unsigned char*>(&encoded[0]),
      reinterpret_cast<const unsigned char*>(input.data()),
      input.size());
    encoded.resize(actual_length);  // Trim to actual length
    return encoded;
}

std::string GetResponseBody(Cronet_EnginePtr cronet_engine,
                            const std::string& url,
                            Cronet_ExecutorPtr executor) {
  SampleUrlRequestCallback url_request_callback;
  Cronet_UrlRequestPtr request = Cronet_UrlRequest_Create();
  Cronet_UrlRequestParamsPtr request_params = Cronet_UrlRequestParams_Create();
  Cronet_UrlRequestParams_http_method_set(request_params, "GET");

  Cronet_UrlRequest_InitWithParams(
      request, cronet_engine, url.c_str(), request_params,
      url_request_callback.GetUrlRequestCallback(), executor);
  Cronet_UrlRequestParams_Destroy(request_params);

  Cronet_UrlRequest_Start(request);
  url_request_callback.WaitForDone();
  Cronet_UrlRequest_Destroy(request);

  return url_request_callback.response_as_string();
}

Cronet_EnginePtr CreateCronetEngine() {
  Cronet_EnginePtr cronet_engine = Cronet_Engine_Create();
  Cronet_EngineParamsPtr engine_params = Cronet_EngineParams_Create();
  Cronet_EngineParams_user_agent_set(engine_params, "CronetSample/1");

  // Get the OHTTP config for use in our envoy URL.
  Cronet_Engine_StartWithParams(cronet_engine, engine_params);
  SampleExecutor executor;
  std::string config = GetResponseBody(
    cronet_engine, "https://ohttp-gateway.jthess.com/gog/ohttp-keys",
    executor.GetExecutor());
  std::string config_as_base64 = base64_encode(config);
  Cronet_Engine_Shutdown(cronet_engine);

  std::string envoy_url = "envoy://"
      "?url=https%3A%2F%2Fohttp-relay.jthess.com" // Relay
      "&ohttp=1" // Flag to indicate this is an ohttp relay
      "&ohttp_gateway=ohttp-gateway.jthess.com/gog/gateway"
      "&ohttp_config=";

  envoy_url = envoy_url + config_as_base64;
  Cronet_EngineParams_envoy_url_set(engine_params, envoy_url.c_str());
  Cronet_EngineParams_enable_quic_set(engine_params, true);

  Cronet_Engine_StartWithParams(cronet_engine, engine_params);
  Cronet_EngineParams_Destroy(engine_params);
  // Use that engine to get the OHTTP config.
  return cronet_engine;
}

void PerformRequest(Cronet_EnginePtr cronet_engine,
                    const std::string& url,
                    Cronet_ExecutorPtr executor) {
  std::string response = GetResponseBody(cronet_engine, url, executor);
  std::cout << "Response to caller: " << std::endl << std::endl << response << std::endl;
}

// Download a resource from the Internet. Optional argument must specify
// a valid URL.
int main(int argc, const char* argv[]) {
  std::cout << "Hello from Cronet!\n";
  Cronet_EnginePtr cronet_engine = CreateCronetEngine();
  std::cout << "  Cronet version: "
            << Cronet_Engine_GetVersionString(cronet_engine) << std::endl;

  std::string url(argc > 1 ? argv[1] : "https://www.example.com");
  std::cout << "  GETting URL: " << url << " via OHTTP" << std::endl;
  SampleExecutor executor;
  PerformRequest(cronet_engine, url, executor.GetExecutor());

  Cronet_Engine_Shutdown(cronet_engine);
  Cronet_Engine_Destroy(cronet_engine);
  return 0;
}
