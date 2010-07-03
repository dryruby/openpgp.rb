module OpenPGP
  module Random
    ##
    # Generates a random number.
    #
    # @param  [Integer]                bits
    # @param  [Hash{Symbol => Object}] options
    # @return [Integer]
    def self.number(bits = 32, options = {})
      octets = bytes((bits / 8.0).ceil).unpack('C*')
      number = octets.inject { |number, octet| number = (number << 8) | octet }
      number & ((1 << bits) - 1)
    end

    ##
    # Generates a pseudo-random prime number of the specified bit length.
    #
    # @param  [Integer]                bits
    # @param  [Hash{Symbol => Object}] options
    # @return [Integer]
    # @see    http://openssl.org/docs/crypto/BN_generate_prime.html
    # @see    http://openssl.org/docs/apps/genrsa.html
    def self.prime(bits, options = {})
      raise NotImplementedError # TODO
    end

    ##
    # Generates a random byte.
    #
    # @return [String]
    def self.byte() bytes(1) end

    ##
    # Generates a string of random bytes.
    #
    # @param  [Integer] count
    # @return [String]
    def self.bytes(count, &block)
      octets = File.open('/dev/urandom', 'r') {|f| f.read(count) } # FIXME
      block_given? ? octets.each_byte(&block) : octets
    end
  end
end
