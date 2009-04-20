require 'openpgp/version'

module OpenPGP
  autoload :Armor,     'openpgp/armor'
  autoload :Message,   'openpgp/message'
  autoload :Packet,    'openpgp/packet'
  autoload :Algorithm, 'openpgp/algorithm'
  autoload :GnuPG,     'openpgp/gnupg'

  ##
  # Alias for OpenPGP::Armor.encode().
  def self.enarmor(data, marker = 'MESSAGE', headers = {})
    Armor.encode(data, marker, headers)
  end

  ##
  # Alias for OpenPGP::Armor.decode().
  def self.dearmor(text, marker = nil)
    Armor.decode(text, marker)
  end
end
