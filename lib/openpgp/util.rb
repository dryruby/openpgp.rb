module OpenPGP
  ##
  # Alias for {OpenPGP::Armor.encode}.
  def self.enarmor(data, marker = :message, options = {})
    Armor.encode(data, marker, options)
  end

  ##
  # Alias for {OpenPGP::Armor.decode}.
  def self.dearmor(text, marker = nil, options = {})
    Armor.decode(text, marker, options)
  end

  ##
  # Alias for {OpenPGP::Message.encrypt}.
  def self.encrypt(data, options = {})
    (msg = Message.encrypt(data, options)) ? msg.to_s : nil
  end

  ##
  # Alias for {OpenPGP::Message.decrypt}.
  def self.decrypt(data, options = {})
    raise NotImplementedError # TODO
  end

  ##
  # Alias for {OpenPGP::Message.sign}.
  def self.sign
    raise NotImplementedError # TODO
  end

  ##
  # Alias for {OpenPGP::Message.verify}.
  def self.verify
    raise NotImplementedError # TODO
  end

  ##
  # @see http://tools.ietf.org/html/rfc4880#section-6.1
  CRC24_INIT = 0x00b704ce
  CRC24_POLY = 0x01864cfb

  ##
  # @param  [String] data
  # @return [Integer]
  # @see    http://tools.ietf.org/html/rfc4880#section-6
  # @see    http://tools.ietf.org/html/rfc4880#section-6.1
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
  # @param  [String] data
  # @return [Integer]
  # @see    http://tools.ietf.org/html/rfc4880#section-3.2
  def self.bitlength(data)
    data.empty? ? 0 : (data.size - 1) * 8 + (Math.log(data[0]) / Math.log(2)).floor + 1
  end
end
