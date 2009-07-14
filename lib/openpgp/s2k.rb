module OpenPGP
  ##
  # OpenPGP string-to-key (S2K) specifiers.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-3.7
  class S2K
    attr_accessor :passphrase
    attr_accessor :algorithm

    def self.identifier
      const_get(:IDENTIFIER)
    end

    def initialize(passphrase = nil, options = {}, &block)
      @passphrase = passphrase.to_s
      options.each { |k, v| instance_variable_set("@#{k}", v) }

      block.call(self) if block_given?
    end

    def to_hash
      {:mode => self.class.identifier, :algorithm => digest.to_i}
    end

    def to_key(key_size = 16)
      key = if digest.size >= key_size
       digest.digest(digest_input)
      else
       Buffer.write do |buffer|
         (key_size / digest.size.to_f).ceil.times do |i|
           buffer << digest.digest(("\0" * i) << digest_input)
         end
       end
      end
      key[0, key_size]
    end

    def digest
      @digest ||= case algorithm
        when nil    then Digest::SHA1
        when Digest then algorithm
        when Symbol then Digest.for(algorithm)
        when String then Digest.for(algorithm)
        else Digest.for(algorithm.to_i)
      end
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.7.1.1
    class Simple < S2K
      IDENTIFIER = 0x00

      def digest_input
        passphrase
      end
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.7.1.2
    class Salted < S2K
      IDENTIFIER = 0x01

      attr_accessor :salt

      def initialize(passphrase = nil, options = {})
        super(passphrase, options)

        @salt = Random.random_bytes(8) unless @salt
      end

      def digest_input
        salt.to_s[0, 8] << passphrase
      end

      def to_hash
        super.merge({:salt => salt})
      end
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.7.1.3
    class Iterated < Salted
      IDENTIFIER = 0x03

      attr_accessor :count

      def to_hash
        super.merge({:count => count}) # FIXME
      end
    end
  end
end
