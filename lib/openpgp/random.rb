module OpenPGP
  module Random
    ##
    # Generates a random number.
    def self.number(bits = 32, options = {})
      octets = bytes((bits / 8.0).ceil).unpack('C*')
      number = octets.inject { |number, octet| number = (number << 8) | octet }
      number & ((1 << bits) - 1)
    end

    ##
    # Generates a pseudo-random prime number of the specified bit length.
    #
    # @see http://openssl.org/docs/crypto/BN_generate_prime.html
    # @see http://openssl.org/docs/apps/genrsa.html
    def self.prime(bits, options = {})
      raise NotImplementedError # TODO
    end

    ##
    # Generates a random byte.
    def self.byte() bytes(1) end

    ##
    # Generates a string of random bytes.
    def self.bytes(count, &block)
      octets = File.open('/dev/urandom', 'r') {|f| f.read(count) } # FIXME
      block_given? ? octets.each_byte(&block) : octets
    end
  end
end
