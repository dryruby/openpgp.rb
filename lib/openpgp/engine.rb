module OpenPGP
  class Engine
    autoload :GnuPG,   'openpgp/engine/gnupg'
    autoload :OpenSSL, 'openpgp/engine/openssl'

    def self.available?
      false
    end

    def self.load!() end

    def self.use(&block)
      load!
      block.call(self)
    end
  end
end
