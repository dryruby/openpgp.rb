require 'openpgp/version'
require 'openpgp/util'

module OpenPGP
  autoload :Algorithm, 'openpgp/algorithm'
  autoload :Armor,     'openpgp/armor'
  autoload :Buffer,    'openpgp/buffer'
  autoload :Cipher,    'openpgp/cipher'
  autoload :Message,   'openpgp/message'
  autoload :Packet,    'openpgp/packet'

  autoload :GnuPG,     'openpgp/gnupg'
end
