require 'openpgp/version'
require 'openpgp/util'

module OpenPGP
  autoload :Algorithm, 'openpgp/algorithm'
  autoload :Armor,     'openpgp/armor'
  autoload :Buffer,    'openpgp/buffer'
  autoload :Cipher,    'openpgp/cipher'
  autoload :Digest,    'openpgp/digest'
  autoload :Message,   'openpgp/message'
  autoload :Packet,    'openpgp/packet'
  autoload :Random,    'openpgp/random'
  autoload :S2K,       'openpgp/s2k'

  autoload :GnuPG,     'openpgp/gnupg'
end
