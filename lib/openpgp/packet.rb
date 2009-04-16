module OpenPGP
  ##
  # OpenPGP packet.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-4.1
  # @see http://tools.ietf.org/html/rfc4880#section-4.3
  class Packet
    attr_accessor :tag
    attr_accessor :size

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-4.2
    def self.parse(data)
      # TODO
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-4.2.2
    def self.parse_new_format(data)
      # TODO
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-4.2.1
    def self.parse_old_format(data)
      # TODO
    end

    def initialize(tag = nil, size = 0)
      @tag, @size = tag, size
    end
  end
end
