module OpenPGP
  class Cipher
    ##
    class Blowfish < Cipher
      IDENTIFIER = 4
      ENGINE     = 'BF-ECB'
    end
  end
end
