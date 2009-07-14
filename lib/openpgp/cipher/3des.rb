module OpenPGP
  class Cipher
    ##
    class TripleDES < Cipher
      IDENTIFIER = 2
      ENGINE     = 'DES-EDE3'
    end
  end
end
