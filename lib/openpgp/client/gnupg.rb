module OpenPGP module Client
  ##
  # GNU Privacy Guard (GnuPG) implementation.
  #
  # @see http://www.gnupg.org/
  class GnuPG
    VERSION = OpenPGP::VERSION

    attr_accessor :options

    def initialize(options = {})
      @options = {
        :homedir => ENV['GNUPGHOME'] || '~/.gnupg',
        :version => false,
      }
      @options.merge!(options)

      if options.has_key?(:options)
        parse_options_file(options[:options])
      end
    end

    # Commands not specific to the function

    ##
    # Prints the program version and licensing information.
    #
    # @return [void]
    def version
      puts "gpg.rb (GnuPG compatible) #{VERSION}"
      puts
      puts "Home: #{options[:homedir]}"
      puts "Supported algorithms:"
      puts "Pubkey: " # TODO
      puts "Cipher: #{cipher_algorithms.keys.map(&:to_s).sort.join(', ')}"
      puts "Hash: #{digest_algorithms.join(', ')}"
      puts "Compression: #{compress_algorithms.keys.map(&:to_s).sort.join(', ')}"
    end

    ##
    # Prints a usage message summarizing the most useful command-line
    # options.
    #
    # @return [void]
    def help() end

    ##
    # Prints warranty information.
    #
    # @return [void]
    def warranty
      raise NotImplementedError
    end

    ##
    # Prints a list of all available options and commands.
    #
    # @return [void]
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
    #
    # @return [void]
    def sign
      raise NotImplementedError # TODO
    end

    ##
    # Makes a clear text signature.
    #
    # @return [void]
    def clearsign
      raise NotImplementedError # TODO
    end

    ##
    # Makes a detached signature.
    #
    # @return [void]
    def detach_sign
      raise NotImplementedError # TODO
    end

    ##
    # Encrypts data.
    #
    # @return [void]
    def encrypt
      raise NotImplementedError # TODO
    end

    ##
    # Encrypts with a symmetric cipher using a passphrase.
    #
    # @param  [String, #to_s] file
    # @return [void]
    def symmetric(file)
      print OpenPGP.encrypt(File.read(file), {
        :symmetric  => true,
        :passphrase => read_passphrase,
        :cipher     => cipher_algorithm,
        :digest     => digest_algorithm,
        :compress   => compress_algorithm,
      })
    end

    ##
    # Stores only (make a simple RFC1991 literal data packet).
    #
    # @param  [String, #to_s] file
    # @return [void]
    def store(file)
      Message.write(stdout) do |msg|
        msg << Packet::LiteralData.new({
          :format    => :b,
          :filename  => File.basename(file),
          :timestamp => File.mtime(file),
          :data      => File.read(file),
        })
      end
    end

    ##
    # Decrypts data.
    #
    # @param  [String, #to_s] file
    # @return [void]
    def decrypt(file)
      raise NotImplementedError # TODO
    end

    ##
    # Verifies data.
    #
    # @param  [String, #to_s] file
    # @return [void]
    def verify(file)
      raise NotImplementedError # TODO
    end

    ##
    # Identical to `--multifile --verify`.
    #
    # @param  [Array<String>] files
    # @return [void]
    def verify_files(*files)
      options[:multifile] = true
      files.each { |file| verify(file) }
    end

    ##
    # Identical to `--multifile --encrypt`.
    #
    # @param  [Array<String>] files
    # @return [void]
    def encrypt_files(*files)
      options[:multifile] = true
      files.each { |file| encrypt(file) }
    end

    ##
    # Identical to `--multifile --decrypt`.
    #
    # @param  [Array<String>] files
    # @return [void]
    def decrypt_files(*files)
      options[:multifile] = true
      files.each { |file| decrypt(file) }
    end

    ##
    # Lists keys from the public keyrings.
    #
    # @param  [Array<String>] keys
    # @return [void]
    def list_keys(*keys)
      list_public_keys(*keys)
    end

    ##
    # Lists keys from the public keyrings.
    #
    # @param  [Array<String>] keys
    # @return [void]
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
    #
    # @param  [Array<String>] keys
    # @return [void]
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
    # Same as {#list_keys}, but the signatures are listed too.
    #
    # @return [void]
    def list_sigs
      raise NotImplementedError # TODO
    end

    ##
    # Same as {#list_sigs}, but the signatures are verified.
    #
    # @return [void]
    def check_sigs
      raise NotImplementedError # TODO
    end

    ##
    # Lists all keys (or the specified ones) along with their fingerprints.
    #
    # @param  [Array<String>] keys
    # @return [void]
    def fingerprint(*keys)
      options[:fingerprint] = true
      list_keys(*keys)
    end

    ##
    # Lists only the sequence of packets.
    #
    # @return [void]
    def list_packets
      raise NotImplementedError # TODO
    end

    ##
    # Presents a menu to work with a smartcard.
    #
    # @return [void]
    def card_edit
      raise NotImplementedError # TODO
    end

    ##
    # Shows the content of the smart card.
    #
    # @return [void]
    def card_status
      raise NotImplementedError # TODO
    end

    ##
    # Presents a menu to allow changing the PIN of a smartcard.
    #
    # @return [void]
    def change_pin
      raise NotImplementedError # TODO
    end

    ##
    # Removes key from the public keyring.
    #
    # @param  [String, #to_s] name
    # @return [void]
    def delete_key(name)
      raise NotImplementedError # TODO
    end

    ##
    # Removes key from the secret and public keyring.
    #
    # @param  [String, #to_s] name
    # @return [void]
    def delete_secret_key(name)
      raise NotImplementedError # TODO
    end

    ##
    # Removes key from the secret and public keyring. If a secret key
    # exists, it will be removed first.
    #
    # @param  [String, #to_s] name
    # @return [void]
    def delete_secret_and_public_key(name)
      raise NotImplementedError # TODO
    end

    ##
    # Exports keys from the public keyring.
    #
    # @param  [Array<String>] keys
    # @return [void]
    def export(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Sends keys to a keyserver.
    #
    # @param  [Array<String>] keys
    # @return [void]
    def send_keys(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Exports the secret keys.
    #
    # @return [void]
    def export_secret_keys
      raise NotImplementedError # TODO
    end

    ##
    # Exports the secret subkeys.
    #
    # @return [void]
    def export_secret_subkeys
      raise NotImplementedError # TODO
    end

    ##
    # Imports/merges keys, adding the given `keys` to the keyring.
    #
    # @param  [Array<String>] keys
    # @return [void]
    def import(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Alias for {#import}.
    #
    # @param  [Array<String>] keys
    # @return [void]
    def fast_import(*keys)
      import(*keys)
    end

    ##
    # Imports the `keys` with the given key IDs from a keyserver.
    #
    # @param  [Array<String>] keys
    # @return [void]
    def recv_keys(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Requests updates from a keyserver for keys that already exist on the
    # local keyring.
    #
    # @param  [Array<String>] keys
    # @return [void]
    def refresh_keys(*keys)
      raise NotImplementedError # TODO
    end

    ##
    # Searches the keyserver for the given `names`.
    #
    # @param  [Array<String>] names
    # @return [void]
    def search_keys(*names)
      raise NotImplementedError # TODO
    end

    ##
    # Retrieves keys located at the specified URIs.
    #
    # @param  [Array<String>] uris
    # @return [void]
    def fetch_keys(*uris)
      require 'open-uri'
      raise NotImplementedError # TODO
    end

    ##
    # Does trust database maintenance.
    #
    # @return [void]
    def update_trustdb
      raise NotImplementedError # TODO
    end

    ##
    # Does trust database maintenance without user interaction.
    #
    # @return [void]
    def check_trustdb
      raise NotImplementedError # TODO
    end

    ##
    # Sends the ownertrust values to `stdout`.
    #
    # @return [void]
    def export_ownertrust
      raise NotImplementedError # TODO
    end

    ##
    # Updates the trustdb with the ownertrust values stored in `files` or
    # `stdin`.
    #
    # @param  [Array<String>] files
    # @return [void]
    def import_ownertrust(*files)
      raise NotImplementedError # TODO
    end

    ##
    # Creates signature caches in the keyring.
    #
    # @return [void]
    def rebuild_keydb_caches
      raise NotImplementedError # TODO
    end

    ##
    # Prints message digest of algorithm `algo` for all given `files` or
    # `stdin`.
    #
    # @param  [String, #to_s] algo
    # @param  [Array<String>] files
    # @return [void]
    def print_md(algo, *files)
      unless digest_algorithms.include?(algorithm = algo.to_s.upcase.to_sym)
        abort "gpg: invalid hash algorithm `#{algo}'"
      else
        digest = Digest.for(algorithm)
      end

      files.each do |file|
        puts (prefix = "#{file}: ") << format_fingerprint(digest.file(file).hexdigest, prefix.size)
      end
    end

    ##
    # Prints message digests of all available algorithms for all given
    # `files` or `stdin`.
    #
    # @param  [Array<String>] files
    # @return [void]
    def print_mds(*files)
      files.each do |file|
        digest_algorithms.each do |algorithm|
          algorithm = :RMD160 if algorithm == :RIPEMD160
          digest    = Digest.for(algorithm)

          puts (prefix = "#{file}: #{algorithm.to_s.rjust(6)} = ") << format_fingerprint(digest.file(file).hexdigest, prefix.size)
        end
      end
    end

    ##
    # Emits `count` random bytes of the given quality level.
    #
    # @param  [Integer, #to_i] level
    # @param  [Integer, #to_i] count
    # @return [void]
    def gen_random(level = 0, count = nil)
      wrong_args "--gen-random 0|1|2 [count]" unless (0..2).include?(level)

      require 'openssl'
      count   = count.to_i if count
      endless = count.nil?
      while endless || count > 0
        n = !endless && count < 99 ? count : 99
        p = Random.bytes(n)
        print options[:armor] ? [p].pack('m').delete("\n") : p
        count -= n unless endless
      end
      puts if options[:armor]
    end

    ##
    # Generates a prime number.
    #
    # @param  [Integer, #to_i] mode
    # @param  [Integer, #to_i] bits
    # @param  [Integer, #to_i] qbits
    # @return [void]
    def gen_prime(mode, bits, qbits = nil)
      case mode.to_i
        when 1..4
          raise NotImplementedError # TODO
        else
          wrong_args "--gen-prime mode bits [qbits]"
      end
    end

    ##
    # Packs an arbitrary input into an OpenPGP ASCII armor.
    #
    # @param  [String, #to_s] file
    # @return [void]
    def enarmor(file)
      text = OpenPGP.enarmor(File.read(file), :armored_file, :comment => 'Use "gpg --dearmor" for unpacking', :line_length => 64)
      puts text # FIXME
    end

    ##
    # Unpacks an arbitrary input from an OpenPGP ASCII armor.
    #
    # @param  [String, #to_s] file
    # @return [void]
    def dearmor(file)
      data = OpenPGP.dearmor(File.read(file))
      puts data # FIXME
    end

    # Commands for key management

    ##
    # Generates a new key pair.
    #
    # @return [void]
    def gen_key
      raise NotImplementedError # TODO
    end

    ##
    # Generates a revocation certificate for the complete key.
    #
    # @param  [String, #to_s] name
    # @return [void]
    def gen_revoke(name)
      raise NotImplementedError # TODO
    end

    ##
    # Generates a designated revocation certificate for a key.
    #
    # @param  [String, #to_s] name
    # @return [void]
    def desig_revoke(name)
      raise NotImplementedError # TODO
    end

    ##
    # Presents a menu which enables you to do most of the key management
    # related tasks.
    #
    # @param  [String, #to_s] key
    # @return [void]
    def edit_key(key)
      raise NotImplementedError # TODO
    end

    ##
    # Signs a public key with your secret key.
    #
    # @param  [String, #to_s] name
    # @return [void]
    def sign_key(name)
      raise NotImplementedError # TODO
    end

    ##
    # Signs a public key with your secret key but marks it as
    # non-exportable.
    #
    # @param  [String, #to_s] name
    # @return [void]
    def lsign_key(name)
      raise NotImplementedError # TODO
    end

    protected

      ##
      # @return [IO]
      def stdin()  $stdin  end

      ##
      # @return [IO]
      def stdout() $stdout end

      ##
      # @return [IO]
      def stderr() $stdout end

      ##
      # @return [String]
      def read_passphrase
        if options[:passphrase]
          options[:passphrase]
        else
          # TODO
        end
      end

      ##
      # @return [Hash]
      def public_keyrings
        {public_keyring_file => keyring(public_keyring_file)} # FIXME
      end

      ##
      # @return [Hash]
      def secret_keyrings
        {secret_keyring_file => keyring(secret_keyring_file)} # FIXME
      end

      ##
      # @param  [String, #to_s] file
      # @return [Message]
      def keyring(file)
        OpenPGP::Message.parse(File.read(File.expand_path(file)))
      end

      ##
      # @return [String]
      def public_keyring_file
        File.join(options[:homedir], 'pubring.gpg')
      end

      ##
      # @return [String]
      def secret_keyring_file
        File.join(options[:homedir], 'secring.gpg')
      end

      ##
      # @return [String]
      def trustdb_file
        File.join(options[:homedir], 'trustdb.gpg')
      end

      ##
      # @param  [Packet]          packet
      # @param  [Symbol, #to_sym] type
      # @return [void]
      def print_key_listing(packet, type)
        puts unless (is_sub_key = [:sub, :ssb].include?(type))
        puts "#{type}   #{format_keyspec(packet)} #{Time.at(packet.timestamp).strftime('%Y-%m-%d')}"
        if options[:fingerprint] && !is_sub_key
          puts "      Key fingerprint = #{format_fingerprint(packet.fingerprint)}"
        end
      end

      ##
      # @param  [Packet, #to_s] packet
      # @return [void]
      def print_uid_listing(packet)
        puts "uid" + (' ' * 18) + packet.to_s
      end

      ##
      # @param  [Packet] key
      # @return [String]
      def format_keyspec(key)
        "____?/#{key.key_id}" # TODO
      end

      ##
      # @param  [String]  input
      # @param  [Integer] column
      # @return [String]
      def format_fingerprint(input, column = 0)
        group_size = case input.size
          when 32 then 2 # MD5
          when 40 then 4 # SHA1, RIPEMD160
                  else 8 # SHA2*
        end

        lines, line, pos = [], '', 0
        input.upcase!
        input.each_byte do |c|
          line << c
          if (pos += 1) % group_size == 0
            if (line.size + column) >= (80 - group_size)
              lines << line
              line, pos = '', 0
            else
              line << ' '
            end
          end
        end
        lines << line.strip unless line.empty?

        output = lines.join($/ + (' ' * column))
        output = output.insert(output.size / 2, ' ') if group_size < 8
        return output
      end

      ##
      # @param  [String, #to_s] file
      # @return [void]
      def parse_options_file(file)
        # TODO
      end

      ##
      # @return [Symbol]
      def cipher_algorithm
        unless options[:cipher_algo]
          Cipher::CAST5 # this is the default cipher
        else
          algorithm = options[:cipher_algo].to_s.upcase.to_sym
          unless cipher_algorithms.has_key?(algorithm)
            abort "gpg: selected cipher algorithm is invalid"
          end
          cipher_algorithms[algorithm]
        end
      end

      ##
      # @return [Symbol]
      def digest_algorithm
        options[:digest_algo]
      end

      ##
      # @return [Symbol]
      def compress_algorithm
        options[:compress_algo]
      end

      ##
      # @return [Hash]
      def cipher_algorithms
        {
          :"3DES"   => Cipher::TripleDES,
          :CAST5    => Cipher::CAST5,
          :BLOWFISH => Cipher::Blowfish,
          :AES      => Cipher::AES128,
          :AES192   => Cipher::AES192,
          :AES256   => Cipher::AES256,
          #:TWOFISH  => Cipher::Twofish, # N/A
        }
      end

      ##
      # @return [Array]
      def digest_algorithms
        [:MD5, :SHA1, :RIPEMD160, :SHA256, :SHA384, :SHA512]
      end

      ##
      # @return [Hash]
      def compress_algorithms
        {
          :none     => nil,
          :ZIP      => nil, # TODO
          :ZLIB     => nil, # TODO
          :BZIP2    => nil, # TODO
        }
      end

      ##
      # @param  [String, #to_s] usage
      # @return [void]
      def wrong_args(usage)
        abort "usage: gpg.rb [options] #{usage}"
      end
  end
end end
