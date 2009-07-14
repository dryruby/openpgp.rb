module OpenPGP
  module Random

    def self.random_bytes(count)
      if Engine::OpenSSL.available?
        Engine::OpenSSL.use do
          OpenSSL::Random.random_bytes(count)
        end
      else
        # TODO
      end
    end

  end
end
