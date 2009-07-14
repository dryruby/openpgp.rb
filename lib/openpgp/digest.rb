module OpenPGP
  ##
  # OpenPGP message digest algorithm.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-9.4
  class Digest
    autoload :MD5,       'openpgp/digest/md5'
    autoload :SHA1,      'openpgp/digest/sha1'
    autoload :RIPEMD160, 'openpgp/digest/rmd160'
    autoload :SHA256,    'openpgp/digest/sha2'
    autoload :SHA384,    'openpgp/digest/sha2'
    autoload :SHA512,    'openpgp/digest/sha2'
    autoload :SHA224,    'openpgp/digest/sha2'

    DEFAULT = SHA1

    def self.for(identifier)
      case identifier
        when Symbol then const_get(identifier.to_s.upcase)
        when String then const_get(identifier.upcase.to_sym)
        when 1      then const_get(:MD5)
        when 2      then const_get(:SHA1)
        when 3      then const_get(:RIPEMD160)
        when 8      then const_get(:SHA256)
        when 9      then const_get(:SHA384)
        when 10     then const_get(:SHA512)
        when 11     then const_get(:SHA224)
      end
    end

    def self.to_i() identifier end

    def self.identifier
      const_get(:IDENTIFIER)
    end

    def self.algorithm
      name.split('::').last.to_sym unless self == Digest
    end

    def self.hexsize
      size * 2
    end

    def self.size
      require 'openssl' unless defined?(::OpenSSL)
      OpenSSL::Digest.new(algorithm.to_s).digest_length
    end

    def self.hexdigest(data)
      require 'openssl' unless defined?(::OpenSSL)
      OpenSSL::Digest.hexdigest(algorithm.to_s, data).upcase
    end

    def self.digest(data)
      require 'openssl' unless defined?(::OpenSSL)
      OpenSSL::Digest.digest(algorithm.to_s, data)
    end
  end
end
