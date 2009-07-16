module OpenPGP
  ##
  # OpenPGP string-to-key (S2K) specifiers.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-3.7
  class S2K
    attr_accessor :passphrase
    attr_accessor :algorithm

    def self.parse(input)
      case mode = input.read_byte
        when 0        then S2K::Simple.parse(input)       # Simple S2K
        when 1        then S2K::Salted.parse(input)       # Salted S2K
        when 3        then S2K::Iterated.parse(input)     # Iterated and Salted S2K
        when 100..110 then S2K.new(:data => input.read)   # Private/Experimental S2K
        else # TODO
      end
    end

    def self.identifier
      const_get(:IDENTIFIER)
    end

    def initialize(passphrase = nil, options = {}, &block)
      @passphrase = passphrase.to_s
      options.each { |k, v| instance_variable_set("@#{k}", v) }

      block.call(self) if block_given?
    end

    def write(buffer)
      buffer.write_byte(identifier)
      buffer.write_byte(digest.to_i)
    end

    def identifier
      @identifier || self.class.identifier
    end

    def to_hash
      {:mode => identifier, :algorithm => digest.to_i}
    end

    def to_s
      Buffer.write { |buffer| write(buffer) }
    end

    def to_key(key_size = 16)
      key = if digest.size >= key_size
        digest.digest(digest_input)
      else
        Buffer.write do |buffer|
          (key_size / digest.size.to_f).ceil.times do |i|
            buffer << digest.digest(digest_input_with_preload(i))
          end
        end
      end
      key[0, key_size]
    end

    def digest
      @digest ||= case algorithm
        when nil    then Digest::DEFAULT
        when Digest then algorithm
        when Symbol then Digest.for(algorithm)
        when String then Digest.for(algorithm)
        else Digest.for(algorithm.to_i)
      end
    end

    def digest_input_with_preload(length = 0)
      ("\0" * length) << digest_input
    end

    def digest_input
      raise NotImplementedError
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.7.1.1
    class Simple < S2K
      IDENTIFIER = 0x00

      def self.parse(input)
        self.new(nil, :algorithm => input.read_byte)
      end

      def digest_input
        passphrase
      end
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.7.1.2
    class Salted < S2K
      IDENTIFIER = 0x01

      def self.parse(input)
        self.new(nil, :algorithm => input.read_byte, :salt => input.read_bytes(8))
      end

      attr_accessor :salt

      def initialize(passphrase = nil, options = {}, &block)
        super(passphrase, options, &block)

        @salt = Random.bytes(8) unless @salt
      end

      def write(buffer)
        super(buffer)
        buffer.write_bytes(salt)
      end

      def to_hash
        super.merge({:salt => salt})
      end

      def digest_input
        salt.to_s[0, 8] << passphrase
      end
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.7.1.3
    class Iterated < Salted
      IDENTIFIER = 0x03

      def self.parse(input)
        self.new(nil, :algorithm => input.read_byte, :salt => input.read_bytes(8)) do |s2k|
          s2k.count = s2k.decode_count(input.read_byte)
        end
      end

      attr_reader :count

      def initialize(passphrase = nil, options = {}, &block)
        super(passphrase, options, &block)

        @count = 65536 unless @count
      end

      def write(buffer)
        super(buffer)
        buffer.write_byte(encode_count(count))
      end

      def to_hash
        super.merge(:count => count)
      end

      def digest_input
        buffer = Buffer.write do |buffer|
          iterations = count
          while iterations > 0
            buffer << (digest_input = super())
            iterations -= digest_input.size
          end
        end
      end

      protected

        EXPBIAS = 6

        def decode_count(count)
          (16 + (count & 15)) << ((count >> 4) + EXPBIAS)
        end

        def encode_count(iterations)
          case iterations
            when 0..1024           then 0
            when 65011712..(1.0/0) then 255
            else
              count1 = iterations >> 6
              count2 = (count2 || 0) + 1 while count1 >= 32 && count1 >>= 1
              result = (count2 << 4) | (count1 - 16)
              result += 1 if decode_count(result) < iterations
              result
          end
        end
    end

    DEFAULT = Iterated
  end
end
