$:.unshift(File.dirname(__FILE__)) unless
  $:.include?(File.dirname(__FILE__)) || $:.include?(File.expand_path(File.dirname(__FILE__)))

module Simplepay
  
  VERSION = '0.2.3' unless const_defined?(:VERSION)

  mattr_accessor :aws_access_key_id
  mattr_accessor :aws_secret_access_key
  mattr_accessor :account_id

  mattr_accessor :submit_method
  @@submit_method = 'post'

  mattr_accessor :use_sandbox
  @@use_sandbox = true

  def self.use_sandbox?
    @@use_sandbox
  end

end

require 'simplepay/constants'
require 'simplepay/support'
require 'simplepay/service'
require 'simplepay/helpers/form_helper'
