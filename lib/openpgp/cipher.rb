require 'openssl'

module OpenPGP
  ##
  # OpenPGP cipher.
  class Cipher
    attr_accessor :key, :options
    attr_accessor :engine

    def initialize(key, options = {})
      @key, @options = key, options
    end

    def identifier
      self.class.const_get(:IDENTIFIER)
    end

    def key_size
      @key_size ||= engine.key_len
    end

    def block_size
      @block_size ||= engine.block_size
    end

    def engine
      @engine ||= self.class.const_get(:ENGINE).new('ECB')
    end

    ##
    # @see http://tools.ietf.org/html/rfc4880#section-13.9
    def encrypt(plaintext)
      ciphertext = String.new

      engine.reset
      engine.encrypt

      # IV
      rblock = OpenSSL::Random.random_bytes(block_size)
      iblock = encrypt_block("\0" * block_size)
      block_size.times do |i|
        ciphertext << (iblock[i] ^= rblock[i]).chr
      end

      # Checksum
      iblock = encrypt_block(iblock)
      ciphertext << (iblock[0] ^ rblock[block_size - 2]).chr
      ciphertext << (iblock[1] ^ rblock[block_size - 1]).chr

      # Resync
      iblock = ciphertext[2..-1]

      # Encrypt
      plaintext.size.times do |n|
        if (i = n % block_size) == 0
          iblock = encrypt_block(iblock)
        end
        ciphertext << (iblock[i] ^= plaintext[n]).chr
      end

      ciphertext
    end

    def decrypt(ciphertext)
      # TODO
      engine.reset
      engine.decrypt
    end

    def encrypt_block(block)
      engine.encrypt
      engine.key = @key
      engine.iv  = (@iv ||= "\0" * engine.iv_len)
      engine.update(block) << engine.final
    end

    ##
    class IDEA < Cipher
      IDENTIFIER = 1
      ENGINE     = OpenSSL::Cipher::IDEA rescue nil
    end

    ##
    class TripleDES < Cipher
      IDENTIFIER = 2
      ENGINE     = Class.new(OpenSSL::Cipher) do
        define_method(:initialize) { |*args| super('DES-EDE3') }
      end
    end

    ##
    class CAST5 < Cipher
      IDENTIFIER = 3
      ENGINE     = OpenSSL::Cipher::CAST5 rescue nil
    end

    ##
    class Blowfish < Cipher
      IDENTIFIER = 4
      ENGINE     = OpenSSL::Cipher::BF rescue nil
    end

    ##
    class AES < Cipher
      ENGINE     = OpenSSL::Cipher::AES128 rescue nil
    end

    ##
    class AES128 < AES
      IDENTIFIER = 7
      ENGINE     = OpenSSL::Cipher::AES128 rescue nil
    end

    ##
    class AES192 < AES
      IDENTIFIER = 8
      ENGINE     = OpenSSL::Cipher::AES192 rescue nil
    end

    ##
    class AES256 < AES
      IDENTIFIER = 9
      ENGINE     = OpenSSL::Cipher::AES256 rescue nil
    end

    ##
    class Twofish < Cipher
      IDENTIFIER = 10
      ENGINE     = nil # TODO: use the 'crypt' gem?
    end
  end
end
