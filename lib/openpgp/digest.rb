require 'digest'

module OpenPGP
  ##
  # OpenPGP digest algorithm.
  module Digest

    def self.for(algorithm)
      case algorithm
        when :MD5
          require 'digest/md5'
          ::Digest::MD5
        when :SHA1
          require 'digest/sha1'
          ::Digest::SHA1
        when :RIPEMD160, :RMD160
          require 'digest/rmd160'
          ::Digest::RMD160
        when :SHA256, :SHA384, :SHA512
          require 'digest/sha2'
          ::Digest::const_get(algorithm)
        when :SHA224
          nil # TODO: use OpenSSL?
        else
          ::Digest::const_get(algorithm)
      end
    end
  end
end
