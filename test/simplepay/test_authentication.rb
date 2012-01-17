require File.dirname(__FILE__) + '/../test_helper'
require 'simplepay/authentication'

class Simplepay::TestAuthentication < Test::Unit::TestCase
  
  context 'Simplepay::Authentication' do
    
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
    
  end
  
end
