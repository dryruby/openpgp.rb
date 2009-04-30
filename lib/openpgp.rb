require 'openpgp/version'
require 'openpgp/util'

module OpenPGP
  autoload :Armor,     'openpgp/armor'
  autoload :Message,   'openpgp/message'
  autoload :Packet,    'openpgp/packet'
  autoload :Algorithm, 'openpgp/algorithm'
  autoload :GnuPG,     'openpgp/gnupg'
end
