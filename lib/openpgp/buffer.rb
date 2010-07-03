require 'stringio'

module OpenPGP
  ##
  class Buffer < StringIO
    ##
    # @return [String]
    def self.write(*args, &block)
      buffer = self.new(*args, &block)
      buffer.string
    end

    ##
    # @yield  [buffer]
    # @yieldparam [Buffer] buffer
    def initialize(*args, &block)
      super
      block.call(self) if block_given?
    end

    ##
    # @return [String]
    def read_string
      read_bytes(length = read_byte)
    end

    ##
    # @param  [String, #to_s] value
    # @return [Buffer]
    def write_string(value)
      value = value.to_s
      self << [value.size].pack('C')
      self << value unless value.empty?
    end

    ##
    # @return [Integer]
    # @see    http://tools.ietf.org/html/rfc4880#section-3.5
    def read_timestamp
      read_unpacked(4, 'N')
    end

    ##
    # @param  [Integer, #to_i] value
    # @return [Buffer]
    # @see    http://tools.ietf.org/html/rfc4880#section-3.5
    def write_timestamp(value)
      self << [value.to_i].pack('N')
    end

    ##
    # @param  [Integer] count
    # @param  [Integer] base
    # @return [Integer]
    # @see    http://tools.ietf.org/html/rfc4880#section-3.1
    def read_number(count, base = nil)
      number, shift = 0, count * 8
      read_bytes(count).each_byte do |octet|
        number += octet << (shift -= 8)
      end
      !base ? number : number.to_s(base).upcase
    end

    ##
    # @param  [Integer] value
    # @return [Buffer]
    # @see    http://tools.ietf.org/html/rfc4880#section-3.1
    def write_number
      # TODO
    end

    ##
    # @return [String]
    # @see    http://tools.ietf.org/html/rfc4880#section-3.2
    def read_mpi
      length = read_unpacked(2, 'n')      # length in bits
      length = ((length + 7) / 8.0).floor # length in bytes
      read_bytes(length)
    end

    ##
    # @param  [String] value
    # @return [Buffer]
    # @see    http://tools.ietf.org/html/rfc4880#section-3.2
    def write_mpi
      # TODO
    end

    ##
    # @return [S2K]
    # @see    http://tools.ietf.org/html/rfc4880#section-3.7
    def read_s2k()     S2K.parse(self) end

    ##
    # @param  [S2K] s2k
    # @return [Buffer]
    def write_s2k(s2k) s2k.write(self) end

    ##
    # @param  [Integer] count
    # @param  [String]  format
    # @return [Integer]
    def read_unpacked(count, format)
      read_bytes(count).unpack(format).first
    end

    ##
    # @param  [Integer] value
    # @return [Buffer]
    def write_unpacked
      # TODO
    end

    ##
    # @param  [Integer] count
    # @return [String]
    def read_bytes(count)
      read(count)
    end

    ##
    # @param  [String] value
    # @return [Buffer]
    def write_bytes(value)
      self << value
    end

    ##
    # @return [String]
    def read_byte
      getc
    end

    ##
    # @param  [#chr, #to_s] value
    # @return [Buffer]
    def write_byte(value)
      self << (value.respond_to?(:chr) ? value : value.to_s[0]).chr
    end
  end
end
