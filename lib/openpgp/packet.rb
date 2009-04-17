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

      Packet.for(tag).new(tag, data.read(data_length))
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

      Packet.for(tag).new(tag, data_length ? data.read(data_length) : data.read)
    end

    def self.for(tag)
      @@tags[tag.to_i] || self
    end

    def initialize(tag = nil, data = nil)
      @tag, @data, @size = tag, data, data ? data.size : 0
    end

    ##
    # OpenPGP Public-Key Encrypted Session Key packet (tag 1).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.1
    class AsymmetricSessionKey < Packet
      # TODO
    end

    ##
    # OpenPGP Signature packet (tag 2).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.2
    class Signature < Packet
      # TODO
    end

    ##
    # OpenPGP Symmetric-Key Encrypted Session Key packet (tag 3).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.3
    class SymmetricSessionKey < Packet
      # TODO
    end

    ##
    # OpenPGP One-Pass Signature packet (tag 4).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.4
    class OnePassSignature < Packet
      # TODO
    end

    ##
    # OpenPGP Public-Key packet (tag 6).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.1
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.2
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class PublicKey < Packet
      # TODO
    end

    ##
    # OpenPGP Public-Subkey packet (tag 14).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.2
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.2
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class PublicSubkey < PublicKey
      # TODO
    end

    ##
    # OpenPGP Secret-Key packet (tag 5).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.3
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.3
    # @see http://tools.ietf.org/html/rfc4880#section-11.2
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class SecretKey < PublicKey
      # TODO
    end

    ##
    # OpenPGP Secret-Subkey packet (tag 7).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.4
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.3
    # @see http://tools.ietf.org/html/rfc4880#section-11.2
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class SecretSubkey < SecretKey
      # TODO
    end

    ##
    # OpenPGP Compressed Data packet (tag 8).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.6
    class CompressedData < Packet
      # TODO
    end

    ##
    # OpenPGP Symmetrically Encrypted Data packet (tag 9).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.7
    class EncryptedData < Packet
      # TODO
    end

    ##
    # OpenPGP Marker packet (tag 10).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.8
    class Marker < Packet
      # TODO
    end

    ##
    # OpenPGP Literal Data packet (tag 11).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.9
    class LiteralData < Packet
      # TODO
    end

    ##
    # OpenPGP Trust packet (tag 12).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.10
    class Trust < Packet
      # TODO
    end

    ##
    # OpenPGP User ID packet (tag 13).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.11
    # @see http://tools.ietf.org/html/rfc2822
    class UserID < Packet
      attr_accessor :name, :comment, :email

      def initialize(tag = nil, data = nil)
        super
        case data
          # User IDs of the form: "name (comment) <email>"
          when /^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$/
            @name, @comment, @email = $1, $2, $3
          # User IDs of the form: "name <email>"
          when /^([^<]+)\s+<([^>]+)>$/
            @name, @comment, @email = $1, nil, $2
          # User IDs of the form: "name"
          when /^([^<]+)$/
            @name, @comment, @email = $1, nil, nil
          # User IDs of the form: "<email>"
          when /^<([^>]+)>$/
            @name, @comment, @email = nil, nil, $2
          else
            @name, @comment, @email = nil
        end
      end

      def to_s
        text = []
        text << name if name
        text << "(#{comment})" if comment
        text << "<#{email}>" if email
        text.join(' ')
      end
    end

    ##
    # OpenPGP User Attribute packet (tag 17).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.12
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    class UserAttribute < Packet
      attr_accessor :packets

      # TODO
    end

    ##
    # OpenPGP Sym. Encrypted Integrity Protected Data packet (tag 18).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.13
    class IntegrityProtectedData < Packet
      # TODO
    end

    ##
    # OpenPGP Modification Detection Code packet (tag 19).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.14
    class ModificationDetectionCode < Packet
      # TODO
    end

    ##
    # OpenPGP Private or Experimental packet (tags 60..63).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-4.3
    class Experimental < Packet; end

    protected
      ##
      # @see http://tools.ietf.org/html/rfc4880#section-4.3
      @@tags = {
         1 => AsymmetricSessionKey,      # Public-Key Encrypted Session Key
         2 => Signature,                 # Signature Packet
         3 => SymmetricSessionKey,       # Symmetric-Key Encrypted Session Key Packet
         4 => OnePassSignature,          # One-Pass Signature Packet
         5 => SecretKey,                 # Secret-Key Packet
         6 => PublicKey,                 # Public-Key Packet
         7 => SecretSubkey,              # Secret-Subkey Packet
         8 => CompressedData,            # Compressed Data Packet
         9 => EncryptedData,             # Symmetrically Encrypted Data Packet
        10 => Marker,                    # Marker Packet
        11 => LiteralData,               # Literal Data Packet
        12 => Trust,                     # Trust Packet
        13 => UserID,                    # User ID Packet
        14 => PublicSubkey,              # Public-Subkey Packet
        17 => UserAttribute,             # User Attribute Packet
        18 => IntegrityProtectedData,    # Sym. Encrypted and Integrity Protected Data Packet
        19 => ModificationDetectionCode, # Modification Detection Code Packet
        60 => Experimental,              # Private or Experimental Values
        61 => Experimental,              # Private or Experimental Values
        62 => Experimental,              # Private or Experimental Values
        63 => Experimental,              # Private or Experimental Values
      }
  end
end
