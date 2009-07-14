module OpenPGP
  module Random
    def self.random_bytes(count)
      require 'openssl' unless defined?(::OpenSSL)
      OpenSSL::Random.random_bytes(count)
    end
  end
end
