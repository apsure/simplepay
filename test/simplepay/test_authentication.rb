require File.dirname(__FILE__) + '/../test_helper'
require 'simplepay/authentication'

class Simplepay::TestAuthentication < Test::Unit::TestCase
  
  context 'Simplepay::Authentication' do
    setup { FakeWeb.clean_registry }
    
    setup do
      @secret_key = "TESTINGKEY"
      @signature  = 'dyk6cZ3K7OyuRrCURgFhhcmrZl37b6FtgE2cTd2nOlU='
      @data = {
        :symbol   => 'string',
        'string'  => 1,
        2         => :symbol,
        'param'   => 'with spaces'
      }
      @auth = Simplepay::Authentication
    end

    should 'compute an Amazon signature for hash data' do
      assert_equal @signature,
        @auth.generate("POST", "http://example.com/foo+bar", @data, @secret_key)
    end

    should 'authenticate correctly signed data' do
      assert @auth.authentic?(@signature, "POST", "http://example.com/foo+bar", @data, @secret_key)
    end

    should 'not validate incorrectly signed data' do
      assert !@auth.authentic?('thisisnotavalidsignaturetoo=', "POST", "http://example.com/foo+bar", @data, @secret_key)
    end

    should 'validate a request w/ successful response' do
      FakeWeb.register_uri :get,
                           /^#{Simplepay::Authentication::SANDBOX_ENDPOINT}.*/,
                           body: SUCCESSFUL_VERIFICATION_RESPONSE

      assert @auth.authentic_request?("http://example.com/URL", {})
    end

    should 'not validate a request w/ an unsuccessful response' do
      FakeWeb.register_uri :get,
                           /^#{Simplepay::Authentication::SANDBOX_ENDPOINT}.*/,
                           body: UNSUCCESSFUL_VERIFICATION_RESPONSE

      assert !@auth.authentic_request?("http://example.com/URL", {})
    end

    should 'not validate a request w/ incorrect success text' do
      FakeWeb.register_uri :get,
                           /^#{Simplepay::Authentication::SANDBOX_ENDPOINT}.*/,
                           body: SUCCESSFUL_ENVELOPE_WITH_UNSUCCESSFUL_TEXT

      assert !@auth.authentic_request?("http://example.com/URL", {})
    end

    should 'use production verification url when certificate url is from production' do
      FakeWeb.register_uri :get,
                           /^#{Simplepay::Authentication::PROD_ENDPOINT}.*/,
                           body: SUCCESSFUL_VERIFICATION_RESPONSE

      assert @auth.authentic_request?("http://example.com/URL", {
        Simplepay::Authentication::CERTIFICATE_URL_PARAM =>
          Simplepay::Authentication::CERTIFICATE_URL_ROOT + "/foobar"
      })
    end

    should 'construct an appropriate parameters for request' do
      query_string = [
        "?Action=VerifySignature",
        "UrlEndPoint=http%3A%2F%2Fexample.com%2FURL",
        "Version=2008-09-17",
        "HttpParameters=amount%3D1%2520USD%26bat%3De~%252F%26foo%252Bbar%3Dbaz",
      ].join("&")

      FakeWeb.register_uri :get,
                           Simplepay::Authentication::SANDBOX_ENDPOINT + query_string,
                           body: SUCCESSFUL_VERIFICATION_RESPONSE

      assert @auth.authentic_request?(
        "http://example.com/URL",
        {"foo+bar" => "baz",
         "amount" => "1 USD",
         "bat" => "e~/" }
      )
    end
  end

  SUCCESSFUL_VERIFICATION_RESPONSE = <<-end_xml
<?xml version="1.0"?>
<VerifySignatureResponse xmlns="http://fps.amazonaws.com/doc/2008-09-17/">
  <VerifySignatureResult>
    <VerificationStatus>Success</VerificationStatus>
  </VerifySignatureResult>
  <ResponseMetadata>
    <RequestId>d09d7197-6f35-4e98-af52-97ef60f7092d:0</RequestId>
  </ResponseMetadata>
</VerifySignatureResponse>
  end_xml

  SUCCESSFUL_ENVELOPE_WITH_UNSUCCESSFUL_TEXT = <<-end_xml
<?xml version="1.0"?>
<VerifySignatureResponse xmlns="http://fps.amazonaws.com/doc/2008-09-17/">
  <VerifySignatureResult>
    <VerificationStatus>NotSuccess</VerificationStatus>
  </VerifySignatureResult>
  <ResponseMetadata>
    <RequestId>d09d7197-6f35-4e98-af52-97ef60f7092d:0</RequestId>
  </ResponseMetadata>
</VerifySignatureResponse>
  end_xml

  UNSUCCESSFUL_VERIFICATION_RESPONSE = <<-end_xml
<?xml version="1.0"?>
<Response>
  <Errors>
    <Error>
      <Code>InvalidSignature</Code>
      <Message>The request signature we calculated does not match the signature you provided.</Message>
    </Error>
  </Errors>
  <RequestID>f5070b91-5462-449a-acc0-3c9d6d6f122e</RequestID>
</Response>
  end_xml

end
