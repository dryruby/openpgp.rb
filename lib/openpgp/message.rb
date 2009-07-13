module OpenPGP
  ##
  # OpenPGP message.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-4.1
  # @see http://tools.ietf.org/html/rfc4880#section-11
  # @see http://tools.ietf.org/html/rfc4880#section-11.3
  class Message
    include Enumerable

    attr_accessor :packets

    ##
    # Creates an encrypted OpenPGP message.
    def self.encrypt(data, options = {}, &block)
      if options[:symmetric]
        key    = (options[:key]    || Digest::SHA1.digest(options[:passphrase]))
        cipher = (options[:cipher] || Cipher::AES128).new(key)

        msg    = self.new do |msg|
          msg << Packet::SymmetricSessionKey.new(:algorithm => cipher.identifier)
          msg << Packet::EncryptedData.new do |packet|
            plaintext = self.write do |msg|
              case data
                when Message then data.each { |packet| msg << packet }
                when Packet  then msg << data
                else msg << Packet::LiteralData.new(:data => data)
              end
            end
            packet.data = cipher.encrypt(plaintext)
          end
        end

        block_given? ? block.call(msg) : msg
      else
        raise NotImplementedError # TODO
      end
    end

    ##
    def self.decrypt(data, options = {}, &block)
      raise NotImplementedError # TODO
    end

    ##
    # Parses an OpenPGP message.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-4.1
    # @see http://tools.ietf.org/html/rfc4880#section-4.2
    def self.parse(data)
      data = Buffer.new(data.to_str) if data.respond_to?(:to_str)

      msg = self.new
      until data.eof?
        if packet = OpenPGP::Packet.parse(data)
          msg << packet
        else
          raise "Invalid OpenPGP message data at position #{data.pos}"
        end
      end
      msg
    end

    def self.write(io = nil, &block)
      data = self.new(&block).to_s
      io.respond_to?(:write) ? io.write(data) : data
    end

    def initialize(*packets, &block)
      @packets = packets.flatten
      block.call(self) if block_given?
    end

    def each(&block) # :yields: packet
      packets.each(&block)
    end

    def to_a
      packets.to_a
    end

    def <<(packet)
      packets << packet
    end

    def empty?
      packets.empty?
    end

    def size
      inject(0) { |sum, packet| sum + packet.size }
    end

    def to_s
      Buffer.write do |buffer|
        packets.each do |packet|
          if body = packet.body
            buffer.write_byte(packet.class.tag | 0xC0)
            buffer.write_byte(body.size)
            buffer.write_bytes(body)
          end
        end
      end
    end
  end
end
