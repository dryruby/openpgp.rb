require 'openssl'

module OpenPGP
  ##
  # OpenPGP cipher algorithm.
  class Cipher
    autoload :IDEA,      'openpgp/cipher/idea'
    autoload :TripleDES, 'openpgp/cipher/3des'
    autoload :CAST5,     'openpgp/cipher/cast5'
    autoload :Blowfish,  'openpgp/cipher/blowfish'
    autoload :AES128,    'openpgp/cipher/aes'
    autoload :AES192,    'openpgp/cipher/aes'
    autoload :AES256,    'openpgp/cipher/aes'
    autoload :Twofish,   'openpgp/cipher/twofish'

    DEFAULT = AES128

    ##
    # @param  [Symbol, String, Integer] identifier
    # @return [Class]
    # @see    http://tools.ietf.org/html/rfc4880#section-9.2
    def self.for(identifier)
      case identifier
        when Symbol then const_get(identifier.to_s.upcase)
        when String then const_get(identifier.upcase.to_sym)
        when 1      then IDEA
        when 2      then TripleDES
        when 3      then CAST5
        when 4      then Blowfish
        when 7      then AES128
        when 8      then AES192
        when 9      then AES256
        when 10     then Twofish
      end
    end

    # @return [S2K]
    attr_accessor :key

    # @return [Hash]
    attr_accessor :options

    # @return [String]
    attr_accessor :engine

    ##
    # @param  [S2K]                    key
    # @param  [Hash{Symbol => Object}] options
    def initialize(key, options = {})
      @key = case key
        when S2K then key.to_key(key_size)
        else S2K::Simple.new(key).to_key(key_size)
      end
      @options = options
    end

    ##
    # @return [Integer]
    def self.to_i() identifier end

    ##
    # @return [Integer]
    def self.identifier
      const_get(:IDENTIFIER)
    end

    ##
    # @return [Integer]
    def identifier()
      self.class.identifier
    end

    ##
    # @return [Integer]
    def key_size
      @key_size ||= engine.key_len
    end

    ##
    # @return [Integer]
    def block_size
      @block_size ||= engine.block_size
    end

    ##
    # @return [String]
    def engine
      @engine ||= Engine::OpenSSL.use do
        OpenSSL::Cipher.new(self.class.const_get(:ENGINE))
      end
    end

    ##
    # @param  [String] plaintext
    # @return [String]
    # @see    http://tools.ietf.org/html/rfc4880#section-13.9
    def encrypt(plaintext)
      ciphertext = String.new

      engine.reset
      engine.encrypt

      # IV
      rblock = Random.bytes(block_size)
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

    ##
    # @param  [String] ciphertext
    # @return [String]
    def decrypt(ciphertext)
      # TODO
      engine.reset
      engine.decrypt
    end

    ##
    # @param  [String] block
    # @return [String]
    def encrypt_block(block)
      engine.encrypt
      engine.key = @key
      engine.iv  = (@iv ||= "\0" * engine.iv_len)
      engine.update(block) << engine.final
    end
  end
end
