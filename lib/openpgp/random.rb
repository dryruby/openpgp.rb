module OpenPGP
  module Random

    ##
    # Generates a random number.
    def self.number(bits = 32, options = {})
      if Engine::OpenSSL.available?
        Engine::OpenSSL.use do
          OpenSSL::BN.rand(bits)
        end
      else
        octets = bytes((bits / 8.0).ceil).unpack('C*')
        number = octets.inject { |number, octet| number = (number << 8) | octet }
        number & ((1 << bits) - 1)
      end
    end

    ##
    # Generates a pseudo-random prime number of the specified bit length.
    #
    # @see http://openssl.org/docs/crypto/BN_generate_prime.html
    # @see http://openssl.org/docs/apps/genrsa.html
    def self.prime(bits, options = {})
      if Engine::OpenSSL.available?
        Engine::OpenSSL.use do
          OpenSSL::BN.generate_prime(bits, options[:safe])
        end
      else
        # TODO
      end
    end

    ##
    # Generates a random byte.
    def self.byte() bytes(1) end

    ##
    # Generates a string of random bytes.
    def self.bytes(count, &block)
      octets = if Engine::OpenSSL.available?
        Engine::OpenSSL.use do
          OpenSSL::Random.random_bytes(count)
        end
      else
        File.open('/dev/urandom', 'r') {|f| f.read(count) } # FIXME
      end
      block_given? ? octets.each_byte(&block) : octets
    end

  end
end
