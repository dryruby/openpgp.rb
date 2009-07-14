module OpenPGP
  class Engine
    class OpenSSL < Engine
      def self.available?
        true # FIXME
      end

      def self.load!
        require 'openssl' unless defined?(::OpenSSL)
      end
    end
  end
end
