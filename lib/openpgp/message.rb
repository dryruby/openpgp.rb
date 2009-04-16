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
      # TODO
    end
  end
end
