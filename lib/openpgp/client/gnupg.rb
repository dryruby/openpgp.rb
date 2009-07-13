module OpenPGP module Client
  ##
  # GNU Privacy Guard (GnuPG) implementation.
  #
  # @see http://www.gnupg.org/
  class GnuPG
    VERSION = OpenPGP::Version::STRING

    attr_accessor :options

    def initialize(options = {})
      @options = {
        :homedir => ENV['GNUPGHOME'] || '~/.gnupg',
      }
      @options.merge!(options)

      if options.has_key?(:options)
        parse_options_file(options[:options])
      end
    end

    # Commands not specific to the function

    ##
    # Prints the program version and licensing information.
    def version
      puts "gpg.rb (GnuPG compatible) #{VERSION}"
      puts
      puts "Home: #{options[:homedir]}"
      puts "Supported algorithms:"
      puts "Pubkey: " # TODO
      puts "Cipher: " # TODO
      puts "Hash: " # TODO
      puts "Compression: " # TODO
    end

    ##
    # Prints a usage message summarizing the most useful command-line options.
    def help() end

    ##
    # Prints warranty information.
    def warranty
      raise NotImplementedError
    end

    ##
    # Prints a list of all available options and commands.
    def dump_options
      self.class.public_instance_methods(false).each do |command|
        if command =~ /^[\w\d_]+$/
          puts "--#{command.to_s.gsub('_', '-')}"
        end
      end
      # TODO: list available options, too.
    end

    # Commands to select the type of operation

    ##
    # Makes a signature.
    def sign
      raise NotImplementedError # TODO
    end

    ##
    # Makes a clear text signature.
    def clearsign
      raise NotImplementedError # TODO
    end

    ##
    # Makes a detached signature.
    def detach_sign
      raise NotImplementedError # TODO
    end

    ##
    # Encrypts data.
    def encrypt
      raise NotImplementedError # TODO
    end

    ##
    # Encrypts with a symmetric cipher using a passphrase.
    def symmetric(file)
      raise NotImplementedError # TODO
    end

    ##
    # Stores only (make a simple RFC1991 literal data packet).
    def store(file)
      raise NotImplementedError # TODO
    end

    ##
    # Decrypts data.
    def decrypt(file)
      raise NotImplementedError # TODO
    end

    ##
    # Verifies data.
    def verify(file)
      raise NotImplementedError # TODO
    end

    ##
    # Identical to --multifile --verify.
    def verify_files(*files)
      options[:multifile] = true
      files.each { |file| verify(file) }
    end

    ##
    # Identical to --multifile --encrypt.
    def encrypt_files(*files)
      options[:multifile] = true
      files.each { |file| encrypt(file) }
    end

    ##
    # Identical to --multifile --decrypt.
    def decrypt_files(*files)
      options[:multifile] = true
      files.each { |file| decrypt(file) }
    end

    ##
    # Lists keys from the public keyrings.
    def list_keys(*keys)
      list_public_keys(*keys)
    end

    ##
    # Lists keys from the public keyrings.
    def list_public_keys(*keys)
      public_keyrings.each do |keyring_filename, keyring|
        puts (keyring_filename = File.expand_path(keyring_filename))
        print '-' * keyring_filename.size

        keyring.each do |packet|
          case packet
            when Packet::PublicSubkey
              print_key_listing(packet, :sub)
            when Packet::PublicKey
              print_key_listing(packet, :pub)
            when Packet::UserID
              print_uid_listing(packet)
          end
        end
      end
    end

    ##
    # Lists keys from the secret keyrings.
    def list_secret_keys(*keys)
      secret_keyrings.each do |keyring_filename, keyring|
        puts (keyring_filename = File.expand_path(keyring_filename))
        print '-' * keyring_filename.size

        keyring.each do |packet|
          case packet
            when Packet::SecretSubkey
              print_key_listing(packet, :ssb)
            when Packet::SecretKey
              print_key_listing(packet, :sec)
            when Packet::UserID
              print_uid_listing(packet)
          end
        end
      end
    end

    ##
    # Same as +list_keys+, but the signatures are listed too.
    def list_sigs
      raise NotImplementedError # TODO
    end

    ##
    # Same as +list_sigs+, but the signatures are verified.
    def check_sigs
      raise NotImplementedError # TODO
    end

    ##
    # Lists all keys (or the specified ones) along with their fingerprints.
    def fingerprint(*keys)
      options[:fingerprint] = true
      list_keys(*keys)
    end

    ##
    # Lists only the sequence of packets.
    def list_packets
      raise NotImplementedError # TODO
    end

    ##
    # Presents a menu to work with a smartcard.
    def card_edit
      raise NotImplementedError # TODO
    end

    ##
    # Shows the content of the smart card.
    def card_status
      raise NotImplementedError # TODO
    end

    ##
    # Presents a menu to allow changing the PIN of a smartcard.
    def change_pin
      raise NotImplementedError # TODO
    end

    ##
    # Removes key from the public keyring.
    def delete_key(name)
      raise NotImplementedError # TODO
    end

    ##
    # Removes key from the secret and public keyring.
    def delete_secret_key(name)
      raise NotImplementedError # TODO
    end

    ##
    # Removes key from the secret and public keyring. If a secret key exists, it will be removed first.
    def delete_secret_and_public_key(name)
      raise NotImplementedError # TODO
    end

    ##
    # Exports keys from the public keyring.
    def export(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Sends keys to a keyserver.
    def send_keys(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Exports the secret keys.
    def export_secret_keys
      raise NotImplementedError # TODO
    end

    ##
    # Exports the secret subkeys.
    def export_secret_subkeys
      raise NotImplementedError # TODO
    end

    ##
    # Imports/merges keys, adding the given keys to the keyring.
    def import(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Alias for +import+.
    def fast_import(*keys)
      import(*keys)
    end

    ##
    # Imports the keys with the given key IDs from a keyserver.
    def recv_keys(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Requests updates from a keyserver for keys that already exist on the local keyring.
    def refresh_keys(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Searches the keyserver for the given names.
    def search_keys(*names)
      raise NotImplementedError # TODO
    end

    ##
    # Retrieves keys located at the specified URIs.
    def fetch_keys(*uris)
      require 'open-uri'
      raise NotImplementedError # TODO
    end

    ##
    # Does trust database maintenance.
    def update_trustdb
      raise NotImplementedError # TODO
    end

    ##
    # Does trust database maintenance without user interaction.
    def check_trustdb
      raise NotImplementedError # TODO
    end

    ##
    # Sends the ownertrust values to stdout.
    def export_ownertrust
      raise NotImplementedError # TODO
    end

    ##
    # Updates the trustdb with the ownertrust values stored in +files+ or stdin.
    def import_ownertrust(*files)
      raise NotImplementedError # TODO
    end

    ##
    # Creates signature caches in the keyring.
    def rebuild_keydb_caches
      raise NotImplementedError # TODO
    end

    ##
    # Prints message digest of algorithm +algo+ for all given files or stdin.
    def print_md(algo, *files)
      raise NotImplementedError # TODO
    end

    ##
    # Prints message digests of all available algorithms for all given files or stdin.
    def print_mds(*files)
      print_md('*', *files)
    end

    ##
    # Emits +count+ random bytes of the given quality level.
    def gen_random(level = 0)
      raise NotImplementedError # TODO
    end

    ##
    def gen_prime(mode, bits)
      raise NotImplementedError # TODO
    end

    ##
    # Packs an arbitrary input into an OpenPGP ASCII armor.
    def enarmor(file)
      raise NotImplementedError # TODO
    end

    ##
    # Unpacks an arbitrary input from an OpenPGP ASCII armor.
    def dearmor(file)
      raise NotImplementedError # TODO
    end

    # Commands for key management

    ##
    # Generates a new key pair.
    def gen_key
      raise NotImplementedError # TODO
    end

    ##
    # Generates a revocation certificate for the complete key.
    def gen_revoke(name)
      raise NotImplementedError # TODO
    end

    ##
    # Generates a designated revocation certificate for a key.
    def desig_revoke(name)
      raise NotImplementedError # TODO
    end

    ##
    # Present a menu which enables you to do most of the key management related tasks.
    def edit_key(key)
      raise NotImplementedError # TODO
    end

    ##
    # Signs a public key with your secret key.
    def sign_key(name)
      raise NotImplementedError # TODO
    end

    ##
    # Signs a public key with your secret key but marks it as non-exportable.
    def lsign_key(name)
      raise NotImplementedError # TODO
    end

    protected

      def public_keyrings
        {public_keyring_file => keyring(public_keyring_file)} # FIXME
      end

      def secret_keyrings
        {secret_keyring_file => keyring(secret_keyring_file)} # FIXME
      end

      def keyring(file)
        OpenPGP::Message.parse(File.read(File.expand_path(file)))
      end

      def public_keyring_file
        File.join(options[:homedir], 'pubring.gpg')
      end

      def secret_keyring_file
        File.join(options[:homedir], 'secring.gpg')
      end

      def trustdb_file
        File.join(options[:homedir], 'trustdb.gpg')
      end

      def print_key_listing(packet, type)
        puts unless (is_sub_key = [:sub, :ssb].include?(type))
        puts "#{type}   #{format_keyspec(packet)} #{Time.at(packet.timestamp).strftime('%Y-%m-%d')}"
        if options[:fingerprint] && !is_sub_key
          puts "      Key fingerprint = #{format_fingerprint(packet.fingerprint)}"
        end
      end

      def print_uid_listing(packet)
        puts "uid" + (' ' * 18) + packet.to_s
      end

      def format_keyspec(key)
        "____?/#{key.key_id}" # TODO
      end

      def format_fingerprint(fingerprint)
        (text = fingerprint.unpack('a4' * (fingerprint.size / 4)).join(' ')).insert(text.size / 2, ' ')
      end

      def parse_options_file(file)
        # TODO
      end
  end

end end
