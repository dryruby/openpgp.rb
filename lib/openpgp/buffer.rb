require 'stringio'

module OpenPGP
  ##
  class Buffer < StringIO
    def self.write(*args, &block)
      buffer = self.new(*args, &block)
      buffer.string
    end

    def initialize(*args, &block)
      super
      block.call(self) if block_given?
    end

    ##
    def read_string
      read_bytes(length = read_byte)
    end

    ##
    def write_string(value)
      value = value.to_s
      self << [value.size].pack('C')
      self << value unless value.empty?
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.5
    def read_timestamp
      read_unpacked(4, 'N')
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.5
    def write_timestamp(value)
      self << [value.to_i].pack('N')
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.1
    def read_number(count, base = nil)
      number, shift = 0, count * 8
      read_bytes(count).each_byte do |octet|
        number += octet << (shift -= 8)
      end
      !base ? number : number.to_s(base).upcase
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.1
    def write_number
      # TODO
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.2
    def read_mpi
      length = read_unpacked(2, 'n')      # length in bits
      length = ((length + 7) / 8.0).floor # length in bytes
      read_bytes(length)
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.2
    def write_mpi
      # TODO
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-3.7
    def read_s2k()     S2K.parse(self) end

    def write_s2k(s2k) s2k.write(self) end

    def read_unpacked(count, format)
      read_bytes(count).unpack(format).first
    end

    def write_unpacked
      # TODO
    end

    def read_bytes(count)
      read(count)
    end

    def write_bytes(value)
      self << value
    end

    def read_byte
      getc
    end

    def write_byte(value)
      self << (value.respond_to?(:chr) ? value : value.to_s[0]).chr
    end
  end
end
