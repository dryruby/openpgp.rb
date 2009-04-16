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
    # @see http://tools.ietf.org/html/rfc4880#section-4.1
    # @see http://tools.ietf.org/html/rfc4880#section-4.2
    def self.parse(data)
      packet = self.new
      # TODO
      packet
    end

    def initialize(packets = [])
      @packets = packets
    end

    def each(&block)
      packets.each(&block)
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
