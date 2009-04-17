module OpenPGP
  ##
  # OpenPGP packet.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-4.1
  # @see http://tools.ietf.org/html/rfc4880#section-4.3
  class Packet
    attr_accessor :tag
    attr_accessor :size
    attr_accessor :data

    ##
    # Parses an OpenPGP packet.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-4.2
    def self.parse(data)
      require 'stringio'
      data = StringIO.new(data.to_str) if data.respond_to?(:to_str)

      unless data.eof?
        new = ((tag = data.getc) & 64).nonzero? # bit 6 indicates new packet format if set
        data.ungetc(tag)
        send(new ? :parse_new_format : :parse_old_format, data)
      end
    end

    ##
    # Parses a new-format (RFC 4880) OpenPGP packet.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-4.2.2
    def self.parse_new_format(data)
      tag = data.getc & 63
      len = data.getc

      case len
        when 0..191   # 4.2.2.1. One-Octet Lengths
          data_length = len
        when 192..223 # 4.2.2.2. Two-Octet Lengths
          data_length = ((len - 192) << 8) + data.getc + 192
        when 224..254 # 4.2.2.4. Partial Body Lengths
          data_length = 1 << (len & 0x1f)
        when 255      # 4.2.2.3. Five-Octet Lengths
          data_length = (data.getc << 24) | (data.getc << 16) | (data.getc << 8) | data.getc
      end

      Packet.new(tag, data.read(data_length))
    end

    ##
    # Parses an old-format (PGP 2.6.x) OpenPGP packet.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-4.2.1
    def self.parse_old_format(data)
      len = (tag = data.getc) & 3
      tag = (tag >> 2) & 15

      case len
        when 0 # The packet has a one-octet length. The header is 2 octets long.
          data_length = data.getc
        when 1 # The packet has a two-octet length. The header is 3 octets long.
          data_length = data.read(2).unpack('n').first
        when 2 # The packet has a four-octet length. The header is 5 octets long.
          data_length = data.read(4).unpack('N').first
        when 3 # The packet is of indeterminate length. The header is 1 octet long.
          data_length = false # read to EOF
        else
          raise "Invalid OpenPGP packet length-type: expected 0..3 but got #{len}"
      end

      Packet.new(tag, data_length ? data.read(data_length) : data.read)
    end

    def initialize(tag = nil, data = nil)
      @tag, @size, @data = tag, data.size, data
    end
  end
end
