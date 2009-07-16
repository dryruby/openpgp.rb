module OpenPGP
  class Engine
    autoload :GnuPG,   'openpgp/engine/gnupg'
    autoload :OpenSSL, 'openpgp/engine/openssl'

    def self.available?
      begin
        load!(true)
        return true
      rescue LoadError => e
        return false
      end
    end

    def self.load!(reload = false)
      raise LoadError
    end

    def self.install!
      load!
    end

    def self.use(&block)
      load!
      block.call(self)
    end

    protected

      def self.install_extensions!(extension)
        name = extension.name.split('::').last.to_sym

        klass = OpenPGP.const_get(name)
        extension.constants.each do |const|
          klass.send(:remove_const, const)
          klass.const_set(const, extension.const_get(const))
        end

        target = (class << klass; self; end)
        extension.instance_methods(false).each do |method|
          target.send(:remove_method, method)
          target.send(:include, extension)
        end
      end
  end
end
