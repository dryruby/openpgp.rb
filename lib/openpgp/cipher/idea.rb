module OpenPGP
  class Cipher
    ##
    class IDEA < Cipher
      IDENTIFIER = 1
      ENGINE     = 'IDEA-ECB'
    end
  end
end
