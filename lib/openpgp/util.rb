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

  ##
  # Returns the bit length of a multiprecision integer (MPI).
  #
  # @see http://tools.ietf.org/html/rfc4880#section-3.2
  def self.bitlength(data)
    (data.size - 1) * 8 + (Math.log(data[0]) / Math.log(2)).floor + 1
  end
end
