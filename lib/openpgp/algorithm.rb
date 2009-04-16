module OpenPGP
  module Algorithm
    ##
    # OpenPGP Public-Key Algorithms.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-9.1
    module Asymmetric
      RSA         = 1
      RSA_ENCRYPT = 2
      RSA_SIGN    = 3
      ELGAMAL     = 16
      DSA         = 17
    end

    ##
    # OpenPGP Symmetric-Key Algorithms.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-9.2
    module Symmetric
      NONE        = 0
      IDEA        = 1
      TRIPLEDES   = 2
      CAST5       = 3
      BLOWFISH    = 4
      AES128      = 7
      AES192      = 8
      AES256      = 9
      TWOFISH     = 10
    end

    ##
    # OpenPGP Compression Algorithms.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-9.3
    module Compression
      NONE        = 0
      ZIP         = 1
      ZLIB        = 2
      BZIP2       = 3
    end

    ##
    # OpenPGP Hash Algorithms.
    #
    # @see http://tools.ietf.org/html/rfc4880#section-9.4
    module Hash
      MD5         = 1
      SHA1        = 2
      RIPEMD160   = 3
      SHA256      = 8
      SHA384      = 9
      SHA512      = 10
      SHA224      = 11
    end
  end
end
