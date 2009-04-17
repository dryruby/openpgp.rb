module OpenPGP
  module Version
    MAJOR = 0
    MINOR = 0
    TINY  = 1
    EXTRA = nil

    STRING = [MAJOR, MINOR, TINY].join('.')
    STRING << "-#{EXTRA}" if EXTRA
  end
end
