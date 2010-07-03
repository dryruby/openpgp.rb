module OpenPGP
  class Digest
    ##
    class SHA224 < Digest
      IDENTIFIER = 11
    end

    ##
    class SHA256 < Digest
      IDENTIFIER = 8
    end

    ##
    class SHA384 < Digest
      IDENTIFIER = 9
    end

    ##
    class SHA512 < Digest
      IDENTIFIER = 10
    end
  end
end
