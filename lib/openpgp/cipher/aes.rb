module OpenPGP
  class Cipher
    ##
    class AES < Cipher
      ENGINE     = 'AES-128-ECB'
    end

    ##
    class AES128 < AES
      IDENTIFIER = 7
      ENGINE     = 'AES-128-ECB'
    end

    ##
    class AES192 < AES
      IDENTIFIER = 8
      ENGINE     = 'AES-192-ECB'
    end

    ##
    class AES256 < AES
      IDENTIFIER = 9
      ENGINE     = 'AES-256-ECB'
    end
  end
end
