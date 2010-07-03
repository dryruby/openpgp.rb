module OpenPGP
  ##
  class Engine
    autoload :GnuPG,   'openpgp/engine/gnupg'
    autoload :OpenSSL, 'openpgp/engine/openssl'

    ##
    # @return [Boolean]
    def self.available?
      begin
        load!(true)
        return true
      rescue LoadError => e
        return false
      end
    end

    ##
    # @param  [Boolean] reload
    # @return [void]
    # @raise  [LoadError]
    def self.load!(reload = false)
      raise LoadError
    end

    ##
    # @return [void]
    # @raise  [LoadError]
    def self.install!
      load!
    end

    ##
    # @yield  [engine]
    # @yieldparam [Engine] engine
    # @return [void]
    def self.use(&block)
      load!
      block.call(self)
    end

    protected

      ##
      # @param  [Module] extension
      # @return [void]
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
