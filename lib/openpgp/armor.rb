module OpenPGP
  ##
  # Alias for OpenPGP::Armor.encode().
  def self.enarmor(data, marker = 'MESSAGE', headers = {})
    Armor.encode(data, marker, headers)
  end

  ##
  # Alias for OpenPGP::Armor.decode().
  def self.dearmor(text, marker = nil)
    Armor.decode(text, marker)
  end

  ##
  # OpenPGP ASCII Armor utilities.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-6.2
  module Armor
    ##
    # @see http://tools.ietf.org/html/rfc4880#section-6.2
    module Markers
      MESSAGE           = 'MESSAGE'
      PUBLIC_KEY_BLOCK  = 'PUBLIC KEY BLOCK'
      PRIVATE_KEY_BLOCK = 'PRIVATE KEY BLOCK'
      SIGNATURE         = 'SIGNATURE'
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-6.2
    def self.header(marker)
      "-----BEGIN #{marker.to_s.upcase}-----"
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-6.2
    def self.footer(marker)
      "-----END #{marker.to_s.upcase}-----"
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-6
    # @see http://tools.ietf.org/html/rfc4880#section-6.2
    # @see http://tools.ietf.org/html/rfc2045
    def self.encode(data, marker = 'MESSAGE', headers = {})
      require 'stringio'
      require 'base64'

      text = StringIO.new
      text << self.header(marker)     << "\n"
      headers.each { |key, value| text << "#{key}: #{value}\n" }
      text << "\n" << Base64.encode64(data)
      text << "="  << Base64.encode64([self.crc24(data)].pack('N')[1, 3])
      text << self.footer(marker)     << "\n"
      text.string
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-6
    # @see http://tools.ietf.org/html/rfc2045
    def self.decode(text, marker = nil)
      # TODO
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-6.1
    CRC24_INIT = 0x00b704ce
    CRC24_POLY = 0x01864cfb

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-6
    # @see http://tools.ietf.org/html/rfc4880#section-6.1
    def self.crc24(data)
      crc = CRC24_INIT
      data.each_byte do |octet|
        crc ^= octet << 16
        8.times do
          crc <<= 1
          crc ^= CRC24_POLY if (crc & 0x01000000).nonzero?
        end
      end
      crc &= 0x00ffffff
    end
  end

  include Armor::Markers
end
