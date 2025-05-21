// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>

#include "cronet_c.h"
#include "sample_executor.h"
#include "sample_url_request_callback.h"

Cronet_EnginePtr CreateCronetEngine() {
  Cronet_EnginePtr cronet_engine = Cronet_Engine_Create();
  Cronet_EngineParamsPtr engine_params = Cronet_EngineParams_Create();
  Cronet_EngineParams_user_agent_set(engine_params, "CronetSample/1");

  Cronet_EngineParams_envoy_url_set(engine_params,
                                    "https://example.com/enovy_path/");
  Cronet_EngineParams_envoy_url_set(
      engine_params,
      "envoy://"
      "?url=https%3A%2F%2Fexample.com%2Fenvoy_path%2F%3Fk1%3Dv1&header_Host="
      "subdomain.example.com&resolve=MAP%20example.com%201.2.3.4");
  // only MAP url-host to address
  Cronet_EngineParams_envoy_url_set(
      engine_params,
      "envoy://"
      "?url=https%3A%2F%2Fexample.com%2Fenvoy_path%2F%3Fk1%3Dv1&header_Host="
      "subdomain.example.com&address=1.2.3.4");
  Cronet_EngineParams_envoy_url_set(
      engine_params,
      "envoy://"
      "?url=https%3A%2F%2Fexample.com%2Fenvoy_path%2F%3Fk1%3Dv1&header_Host="
      "subdomain.example.com&address=1.2.3.4&disabled_cipher_suites=0xc024,0xc02f");
  Cronet_EngineParams_envoy_url_set(
      engine_params,
      "envoy://"
      "?url=https%3A%2F%2Fexample.com%2Fenvoy_path%2F%3Fk1%3Dv1&header_Host="
      "subdomain.example.com&address=1.2.3.4&disabled_cipher_suites=0xc024,0xc02f");
  Cronet_EngineParams_envoy_url_set(engine_params, "socks5://127.0.0.1:1080");
  // proxy URL and SOCKS5 together (for true PTs)
  Cronet_EngineParams_envoy_url_set(
      engine_params,
      "envoy://"
      "?url=https%3A%2F%2Frayon.example.com%2Fwikipedia%2F&address=142.65.13.41"
      "&header_Host=abc.example.com&socks5=socks5%3A%2F%2Flocalhost%3A8192");
 
  Cronet_EngineParams_enable_quic_set(engine_params, true);

  Cronet_Engine_StartWithParams(cronet_engine, engine_params);
  Cronet_EngineParams_Destroy(engine_params);
  return cronet_engine;
}

void PerformRequest(Cronet_EnginePtr cronet_engine,
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

  std::cout << "Response Data:" << std::endl
            << url_request_callback.response_as_string() << std::endl;
}

// Download a resource from the Internet. Optional argument must specify
// a valid URL.
int main(int argc, const char* argv[]) {
  std::cout << "Hello from Cronet!\n";
  Cronet_EnginePtr cronet_engine = CreateCronetEngine();
  std::cout << "Cronet version: "
            << Cronet_Engine_GetVersionString(cronet_engine) << std::endl;

  std::string url(argc > 1 ? argv[1] : "https://www.google.com/generate_204");
  std::cout << "URL: " << url << std::endl;
  SampleExecutor executor;
  PerformRequest(cronet_engine, url, executor.GetExecutor());

  Cronet_Engine_Shutdown(cronet_engine);
  Cronet_Engine_Destroy(cronet_engine);
  return 0;
}
