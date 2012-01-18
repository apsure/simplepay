require 'openssl'
require 'base64'
require 'cgi'
require 'net/http'
require 'rexml/document'

module Simplepay
  ##
  # This module generates RFC-2104-compliant HMAC signatures.  These 
  # signatures are used by both Amazon and you to determine whether or not
  # data transmitted is authentic.  The hash is based on the amazon secret
  # access key, which is a trusted secret between both parties.
  # 
  # === HMAC (RFC-2104 Specification)
  # 
  # For more information about the RFC-2104 spec, 
  # see http://www.ietf.org/rfc/rfc2104.txt
  #
  module Authentication
    CERTIFICATE_URL_ROOT = "https://fps.amazonaws.com/"
    CERTIFICATE_URL_ROOT_SANDBOX = "https://fps.sandbox.amazonaws.com/"
    CERTIFICATE_URL_PARAM = "certificateUrl"

    PROD_ENDPOINT = CERTIFICATE_URL_ROOT
    SANDBOX_ENDPOINT = CERTIFICATE_URL_ROOT_SANDBOX

    STATUS_ELEMENT_PATH = 'VerifySignatureResponse/VerifySignatureResult/VerificationStatus'
    STATUS_SUCCESS_TEXT = 'Success'

    CERT_FILE = File.join File.dirname(File.expand_path(__FILE__)),
                          'amazon-ca-bundle.crt'

    class << self

      def generate(http_method, url, params, secret_access_key = Simplepay.aws_secret_access_key)
        encode(digest(string_to_sign(http_method, url, params), secret_access_key))
      end

      def authentic?(signature, http_method, url, params, secret_access_key = Simplepay.aws_secret_access_key)
        signature == generate(http_method, url, params, secret_access_key)
      end


      def authentic_request?(receiving_endpoint, params)
        endpoint = verification_endpoint params

        url = build_verification_request_url receiving_endpoint, params, endpoint

        response = get_secure_http_response url

        successful_verification_response? response
      end

      private

      def verification_endpoint(params)
        certificate_url = params[CERTIFICATE_URL_PARAM] || ''

        if certificate_url.start_with?(CERTIFICATE_URL_ROOT)
          PROD_ENDPOINT
        else
          SANDBOX_ENDPOINT
        end
      end

      def build_verification_request_url(receiving_endpoint, params, endpoint)
        endpoint + [
          "?Action=VerifySignature",
          "UrlEndPoint=#{urlencode(receiving_endpoint)}",
          "Version=2008-09-17",
          "HttpParameters=#{urlencode(params_as_string(params))}",
        ].join("&")
      end

      def get_secure_http_response(url)
        uri = URI.parse url

        http = Net::HTTP.new uri.host, uri.port
        http.use_ssl = true
        http.ca_file = CERT_FILE
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.verify_depth = 5

        response = http.request_get url
      end

      def successful_verification_response?(response)
        document = REXML::Document.new response.body
        status = document.elements[STATUS_ELEMENT_PATH]

        !status.nil? && (status.text == STATUS_SUCCESS_TEXT)
      end

      def urlencode(plaintext)
        CGI.escape(plaintext.to_s).gsub("+", "%20").gsub("%7E", "~")
      end

      def urlencode_uri(uri)
        urlencode(uri).gsub("%2F", "/")
      end

      def string_to_sign(http_method, url, params)
        uri = URI.parse(url)

        sorted_params = params.map { |k,v| [k.to_s, v.to_s] }.reject { |_,v| v.blank? }.sort
        querystring = sorted_params.map { |k,v| [urlencode(k), urlencode(v)].join('=') }.join('&')

        "#{http_method.to_s.upcase}\n#{uri.host}\n#{urlencode_uri(uri.path.presence || '/')}\n#{querystring}"
      end

      def params_as_string(params)
        sorted_params = params.map { |k,v| [k.to_s, v.to_s] }.reject { |_,v| v.blank? }.sort
        querystring = sorted_params.map { |k,v| [urlencode(k), urlencode(v)].join('=') }.join('&')
      end

      ##
      # Generate an RFC-2104-compliant HMAC
      # 
      def digest(value, secret_access_key)
        digest = OpenSSL::Digest::Digest.new("sha256")
        OpenSSL::HMAC.digest(digest, secret_access_key, value)
      end

      def encode(value)
        Base64.encode64(value).chomp
      end

    end

  end

end
