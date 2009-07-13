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
      ENGINE     = OpenSSL::Cipher::IDEA rescue nil
      IDENTIFIER = 1
    end

    ##
    class TripleDES < Cipher
      ENGINE     = OpenSSL::Cipher::DES rescue nil
      IDENTIFIER = 2
    end

    ##
    class CAST5 < Cipher
      ENGINE     = OpenSSL::Cipher::CAST5 rescue nil
      IDENTIFIER = 3
    end

    ##
    class Blowfish < Cipher
      ENGINE     = OpenSSL::Cipher::BF rescue nil
      IDENTIFIER = 4
    end

    ##
    class AES < Cipher
      ENGINE     = OpenSSL::Cipher::AES128 rescue nil
    end

    ##
    class AES128 < AES
      ENGINE     = OpenSSL::Cipher::AES128 rescue nil
      IDENTIFIER = 7
    end

    ##
    class AES192 < AES
      ENGINE     = OpenSSL::Cipher::AES192 rescue nil
      IDENTIFIER = 8
    end

    ##
    class AES256 < AES
      ENGINE     = OpenSSL::Cipher::AES256 rescue nil
      IDENTIFIER = 9
    end

    ##
    class Twofish < Cipher
      ENGINE     = nil # TODO: use the 'crypt' gem?
      IDENTIFIER = 10
    end
  end
end
