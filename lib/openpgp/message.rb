module OpenPGP
  ##
  # OpenPGP message.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-4.1
  # @see http://tools.ietf.org/html/rfc4880#section-11
  # @see http://tools.ietf.org/html/rfc4880#section-11.3
  class Message
    attr_accessor :packets

    ##
    # Parses an OpenPGP message.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-4.1
    # @see http://tools.ietf.org/html/rfc4880#section-4.2
    def self.parse(data)
      require 'stringio'
      data = StringIO.new(data.to_str) if data.respond_to?(:to_str)

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

    def initialize(packets = [])
      @packets = packets
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
  end
end
