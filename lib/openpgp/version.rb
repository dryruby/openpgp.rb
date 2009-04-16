module OpenPGP
  module VERSION
    MAJOR = 0
    MINOR = 0
    TINY  = 1
    EXTRA = :dev

    STRING = [MAJOR, MINOR, TINY].join('.')
    STRING << "-#{EXTRA}" if EXTRA
  end
end
