#include <vector>

#include "gtest/gtest.h"

#include "ohttp.h"

namespace {

ohttp::OHTTP_HPKE_KEY* getKeys() {
  // Use a newly derived keypair to do a roundtrip.
  ohttp::OHTTP_HPKE_KEY* test_keypair = ohttp::createHpkeKey();
  const ohttp::OHTTP_HPKE_KEM* kem = ohttp::createHpkeKem();
  int rv = ohttp::OHTTP_HPKE_KEY_generate(test_keypair, kem);
  EXPECT_EQ(rv, 1); // Check if key generation was successful
  return test_keypair;
}

TEST(OhttpTest, GetKeyConfig) {
  ohttp::OHTTP_HPKE_KEY* keypair = getKeys();
  std::vector<uint8_t> key_config = ohttp::generate_key_config(keypair);

  // 2 byte length plus one config
  EXPECT_EQ(key_config.size(), size_t(2 + 1 + 2 + 32 + 2 + 4));

  // First 2 bytes are remaining length
  EXPECT_EQ(key_config[0], 0);
  EXPECT_EQ(key_config[1], 1 + 2 + 32 + 2 + 4);
}

TEST(OhttpTest, ExtractPublicKeyFromConfig) {
  ohttp::OHTTP_HPKE_KEY* keypair = getKeys();
  uint8_t public_key[ohttp::OHTTP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t public_key_len;
  EXPECT_TRUE(ohttp::OHTTP_HPKE_KEY_public_key(keypair, public_key, &public_key_len, sizeof(public_key)));
  std::vector<uint8_t> public_key_vec(public_key, public_key + public_key_len);

  std::vector<uint8_t> key_config = ohttp::generate_key_config(keypair);
  std::vector<uint8_t> config_public_key = ohttp::get_public_key(key_config);

  EXPECT_EQ(config_public_key.size(), size_t(32));
  EXPECT_EQ(config_public_key, public_key_vec);
}

// Test encoding strings.
TEST(EncodeStringTest, TestEncodeString) {
  std::string input = "hello";
  // Length is a 2-byte number.
  std::vector<uint8_t> expected = {5, 'h', 'e', 'l', 'l', 'o'};
  EXPECT_EQ(ohttp::encode_string(input), expected);
}

// Test extracting encoded strings.
TEST(DecodeStringTest, TestDecodeString) {
  int starting_offset = 0;
  std::vector<uint8_t> input = {5, 0x42, 0x43, 0x44, 0x45, 0x46, 1, 0x47};
  std::vector<uint8_t> expected = {0x42, 0x43, 0x44, 0x45, 0x46};
  std::vector<uint8_t> output;
  int bytes_used;
  EXPECT_EQ(ohttp::get_next_encoded_string(input, starting_offset, output, bytes_used), ohttp::OhttpParseErrorCode::SUCCESS);
  EXPECT_EQ(output, expected);
  EXPECT_EQ(bytes_used, 6);
  int next_offset = starting_offset + bytes_used;
  expected = {0x47};
  std::vector<uint8_t> output2;
  EXPECT_EQ(ohttp::get_next_encoded_string(input, next_offset, output2, bytes_used), ohttp::OhttpParseErrorCode::SUCCESS);
  EXPECT_EQ(output2, expected);
  EXPECT_EQ(bytes_used, 2);
}

// Test binary request creation per https://www.rfc-editor.org/rfc/rfc9292
TEST(OhttpTest, TestBinaryRequest) {
  std::vector<uint8_t> request =
      ohttp::get_binary_request("POST", "https", "ohttp-gateway.jthess.com", "/", "foo");
  std::vector<uint8_t> expected = {
      // Known-Length Request {
      //   Framing Indicator (i) = 0,
      //   Request Control Data (..),
      //   Known-Length Field Section (..),
      //   Known-Length Content (..),
      //   Known-Length Field Section (..),
      //   Padding (..),
      // }

      // Framing Indicator
      0,

      // Control Data
      // Request Control Data {
      //   Method Length (i),
      4,
      //   Method (..),
      'P', 'O', 'S', 'T',  // Method Length & Method
      //   Scheme Length (i),
      5,
      //   Scheme (..),
      'h', 't', 't', 'p', 's',
      //   Authority Length (i),
      24,
      //   Authority (..),
      'o', 'h', 't', 't', 'p', '-', 'g', 'a', 't', 'e', 'w', 'a', 'y', '.', 'j',
      't', 'h', 'e', 's', 's', '.', 'c', 'o', 'm',
      //   Path Length (i),
      1,
      //   Path (..),
      // }
      '/',

      // Header section.
      // Known-Length Field Section {
      //   Length (i),
      0,
      //   Field Line (..) ...,
      // }

      // Known-Length Content {
      //   Content Length (i),
      3,
      //   Content (..),
      'f', 'o', 'o',
      // }

      // Trailer section.
      // Known-Length Field Section {
      //   Length (i),
      0,
      //   Field Line (..) ...,
      // }
  };
  EXPECT_EQ(request, expected);
}

TEST(OhttpTest, TestBinaryResponse) {
  std::string response_message = "this is a response";
  std::vector<uint8_t> response_message_vec = std::vector<uint8_t>(response_message.begin(), response_message.end());
  std::vector<uint8_t> response = ohttp::get_binary_response(200, response_message_vec);
  std::vector<uint8_t> expected = {
    // Known-Length Response {
    //   Framing Indicator (i) = 1,
    //   Known-Length Informational Response (..) ...,
    //   Final Response Control Data (..),
    //   Known-Length Field Section (..),
    //   Known-Length Content (..),
    //   Known-Length Field Section (..),
    //   Padding (..),
    // }
    1,

    // 64, // XXX this shows up in the data not sure why, is it an informational
        // response?

    // No informational responses in this test.
    // Known-Length Informational Response {
    //   Informational Response Control Data (..),
    //   Known-Length Field Section (..),
    // }

    // Final Response Control Data {
    //   Status Code (i) = 200..599,
    // }
    200,

    // Known-Length Field Section {
    //   Length (i),
    //   Field Line (..) ...,
    // }
    0,

    // Known-Length Content {
    //   Content Length (i),
    //   Content (..),
    // }
    18, // Length of "this is a response"
    't', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 'r', 'e', 's', 'p', 'o', 'n', 's', 'e',

    // Trailer section.
    // Known-Length Field Section {
    //   Length (i),
    //   Field Line (..) ...,
    // }
    0,
  };
  EXPECT_EQ(response, expected);
}

TEST(OhttpTest, EncapsulateAndDecapsulateResponse) {
  ohttp::OHTTP_HPKE_KEY* test_keypair = getKeys();
  uint8_t client_enc[ohttp::OHTTP_HPKE_MAX_ENC_LENGTH];
  size_t client_enc_len;
  uint8_t pkR[ohttp::OHTTP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t pkR_len;
  int rv = ohttp::OHTTP_HPKE_KEY_public_key(
      test_keypair, pkR, &pkR_len, ohttp::OHTTP_HPKE_MAX_PUBLIC_KEY_LENGTH);
  EXPECT_EQ(rv, 1);

  ohttp::OHTTP_HPKE_CTX* sender_context = ohttp::createHpkeContext();
  std::vector<uint8_t> encapsulated_request =
      ohttp::get_encapsulated_request(
        sender_context,
        "POST", "https", "ohttp-gateway.jthess.com", "/", "foo",
        client_enc,
        &client_enc_len,
        pkR,
        pkR_len);
  std::cout << std::endl;
  ohttp::OHTTP_HPKE_CTX* receiver_context = ohttp::createHpkeContext();
  size_t max_req_out_len = encapsulated_request.size();
  std::vector<uint8_t> request_bhttp(max_req_out_len);
  size_t req_out_len;
  size_t enc_len = 32;
  u_int8_t enc[enc_len];
  ohttp::DecapsulationErrorCode rv2 = ohttp::decapsulate_request(
    receiver_context,
    encapsulated_request,
    request_bhttp.data(),
    &req_out_len,
    enc,
    enc_len,
    max_req_out_len,
    test_keypair);
  EXPECT_EQ(rv2, ohttp::DecapsulationErrorCode::SUCCESS);

  // Give a made up response.
  std::vector<uint8_t> encapsulated_response = ohttp::encapsulate_response(
    receiver_context,
    enc,
    enc_len,
    200,
    "this is a response");
  // Be sure its actually populated; we'll verify contents below.
  EXPECT_GT(encapsulated_response.size(), size_t(32 + 18));

  // Then decapsulate the response back at the sender.
  size_t max_resp_out_len = encapsulated_response.size();
  uint8_t response_bhttp[max_resp_out_len];
  size_t resp_out_len;
  ohttp::DecapsulationErrorCode rv3 = ohttp::decapsulate_response(
    sender_context,
    client_enc,
    client_enc_len,
    encapsulated_response,
    response_bhttp,
    &resp_out_len,
    max_resp_out_len);
  EXPECT_EQ(rv3, ohttp::DecapsulationErrorCode::SUCCESS);

  EXPECT_EQ(resp_out_len, size_t(23)); // 18 plus the BHTTP encoding
  EXPECT_EQ(response_bhttp[0], 1);     // Fixed length response
  EXPECT_EQ(response_bhttp[1], 200);   // Status code (Improperly encoded.  Fix this.)
}

TEST(OhttpTest, ParseBinaryRequest)
{
  std::vector<uint8_t> request =
      ohttp::get_binary_request("POST", "https", "ohttp-gateway.jthess.com", "/", "foo");

  std::string method = ohttp::get_method_from_binary_request(request);
  std::string expected_method = "POST";
  EXPECT_EQ(method, expected_method);

  std::string url = ohttp::get_url_from_binary_request(request);
  std::string expected_url = "https://ohttp-gateway.jthess.com/";
  EXPECT_EQ(url, expected_url);

  std::string body = ohttp::get_body_from_binary_request(request);
  std::string expected_body = "foo";
  EXPECT_EQ(body, expected_body);
}

// Test that encapsulation starts with the correct header.
TEST(OhttpTest, TestEncapsulatedRequestHeader) {
  // Encapsulation per RFC 9458:
  // https://www.rfc-editor.org/rfc/rfc9458

  // hdr = concat(encode(1, key_id),
  //              encode(2, kem_id),
  //              encode(2, kdf_id),
  //              encode(2, aead_id))
  // info = concat(encode_str("message/bhttp request"),
  //               encode(1, 0),
  //               hdr)
  // enc, sctxt = SetupBaseS(pkR, info)
  // ct = sctxt.Seal("", request)
  // enc_request = concat(hdr, enc, ct)

  ohttp::OHTTP_HPKE_KEY* test_keypair = getKeys();
  uint8_t client_enc[ohttp::OHTTP_HPKE_MAX_ENC_LENGTH];
  size_t client_enc_len;
  uint8_t pkR[ohttp::OHTTP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t pkR_len;
  int rv = ohttp::OHTTP_HPKE_KEY_public_key(
      test_keypair, pkR, &pkR_len, ohttp::OHTTP_HPKE_MAX_PUBLIC_KEY_LENGTH);
  EXPECT_EQ(rv, 1); // Check if public key retrieval was successful

  ohttp::OHTTP_HPKE_CTX* sender_context = ohttp::createHpkeContext();
  std::vector<uint8_t> request =
      ohttp::get_encapsulated_request(
        sender_context, 
        "POST", "https", "ohttp-gateway.jthess.com", "/", "foo",
        client_enc, &client_enc_len,
        pkR, pkR_len);

  std::vector<uint8_t> expected_hdr = {
      0x80,        // Key ID
      0x00, 0x20,  // HPKE KEM ID
      0x00, 0x01,  // KDF ID
      0x00, 0x01,  // AEAD ID
  };

  // hdr portion of the encapsulated request is the first 7 bytes of request.
  int hdr_length = 7;
  std::vector<uint8_t> actual_hdr(hdr_length);
  std::copy(request.begin() + 0, request.begin() + hdr_length,
            actual_hdr.begin());
  EXPECT_EQ(expected_hdr, actual_hdr);

  // enc and ct vary.  Their creation is outsourced to HPKE implementation from
  // openssl.
}

TEST(OhttpTest, DecapsulateEmptyRequestFails) {
  ohttp::OHTTP_HPKE_KEY* test_keypair = getKeys();
  size_t pkR_len = 32;
  uint8_t pkR[pkR_len];
  size_t written;
  int rv = ohttp::OHTTP_HPKE_KEY_public_key(
      test_keypair, pkR, &written, pkR_len);
  EXPECT_EQ(rv, 1); // Check if public key retrieval was successful

  // Now, decapsulate it with the same keypair
  ohttp::OHTTP_HPKE_CTX* receiver_context = ohttp::createHpkeContext();
  std::vector<uint8_t> empty_request = {};
  std::vector<uint8_t> request_bhttp(0);
  size_t out_len;
  size_t enc_len = 32;
  uint8_t enc[enc_len];
  ohttp::DecapsulationErrorCode rv2 = ohttp::decapsulate_request(
    receiver_context,
    empty_request,
    request_bhttp.data(),
    &out_len,
    enc,
    enc_len,
    0,
    test_keypair);
  EXPECT_EQ(rv2, ohttp::DecapsulationErrorCode::ERR_NO_ENCAPSULATED_HEADER);
}

// Enc/Decapsulate routrip test
TEST(OhttpTest, EncapsulateAndDecapsulateRequest) {
  // Recipient keys
  ohttp::OHTTP_HPKE_KEY* test_keypair = getKeys();
  uint8_t client_enc[ohttp::OHTTP_HPKE_MAX_ENC_LENGTH];
  size_t client_enc_len;
  uint8_t pkR[ohttp::OHTTP_HPKE_MAX_PUBLIC_KEY_LENGTH];
  size_t pkR_len;
  int rv = ohttp::OHTTP_HPKE_KEY_public_key(
      test_keypair, pkR, &pkR_len, ohttp::OHTTP_HPKE_MAX_PUBLIC_KEY_LENGTH);
  EXPECT_EQ(rv, 1); // Check if public key retrieval was successful

  // Encapsulate it
  ohttp::OHTTP_HPKE_CTX* sender_context = ohttp::createHpkeContext();
  std::vector<uint8_t> request =
      ohttp::get_encapsulated_request(
        sender_context,
        "POST", "https", "ohttp-gateway.jthess.com", "/", "foo",
        client_enc, &client_enc_len,
        pkR, pkR_len);

  ohttp::OHTTP_HPKE_CTX* receiver_context = ohttp::createHpkeContext();
  size_t max_out_len = request.size();
  std::vector<uint8_t> request_bhttp(max_out_len);
  size_t out_len;
  size_t enc_len = 32;
  uint8_t enc[enc_len];
  ohttp::DecapsulationErrorCode rv2 = ohttp::decapsulate_request(
    receiver_context,
    request,
    request_bhttp.data(),
    &out_len,
    enc,
    enc_len,
    max_out_len,
    test_keypair);
  EXPECT_EQ(rv2, ohttp::DecapsulationErrorCode::SUCCESS);

  std::vector<uint8_t> expected_bhttp = ohttp::get_binary_request("POST", "https", "ohttp-gateway.jthess.com", "/", "foo");
  EXPECT_EQ(out_len, expected_bhttp.size());
  std::vector<uint8_t> request_bhttp_vec(request_bhttp.data(), request_bhttp.data() + out_len);
  EXPECT_EQ(request_bhttp_vec, expected_bhttp);
}

// Enc/Decapsulate routrip test
TEST(OhttpTest, ParseBHTTPResponse) {
  std::string response_message = "bar";
  std::vector<uint8_t> resp_text = std::vector<uint8_t>(response_message.begin(), response_message.end());
  std::vector<uint8_t> response = ohttp::get_binary_response(200, resp_text);

  std::string parsed_message = ohttp::get_body_from_binary_response(response);
  EXPECT_EQ(parsed_message, response_message);
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
