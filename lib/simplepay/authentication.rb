require 'openssl'
require 'base64'
require 'cgi'

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
    
    class << self
      
      def generate(http_method, url, params, secret_access_key = Simplepay.aws_secret_access_key)
        encode(digest(convert_to_string(http_method, url, params), secret_access_key))
      end
      
      def authentic?(signature, http_method, url, params, secret_access_key = Simplepay.aws_secret_access_key)
        signature == generate(http_method, url, params, secret_access_key)
      end

      private

      def urlencode(plaintext)
        CGI.escape(plaintext.to_s).gsub("+", "%20").gsub("%7E", "~")
      end

      def urlencode_uri(uri)
        urlencode(uri).gsub("%2F", "/")
      end

      ##
      # Converts a Hash of key-value pairs into an Amazon compliant block of
      # signature text.
      # 
      #=== Example
      # 
      #     {:key1 => 'Value1', 'foo' => 3 }
      # 
      # would become
      # 
      #     "foo3key1Value1"
      # 
      def convert_to_string(http_method, url, params)
        uri = URI.parse(url)

        sorted_params = params.map { |k,v| [k.to_s, v.to_s] }.reject { |_,v| v.blank? }.sort
        querystring = sorted_params.map { |k,v| [urlencode(k), urlencode(v)].join('=') }.join('&')

        "#{http_method.to_s.upcase}\n#{uri.host}\n#{urlencode_uri(uri.path.presence || '/')}\n#{querystring}"
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
