OpenPGP.rb: OpenPGP for Ruby
============================

This is a pure-Ruby implementation of the OpenPGP Message Format (RFC 4880).

* <http://openpgp.rubyforge.org/>
* <http://github.com/bendiken/openpgp>

### About OpenPGP

OpenPGP is the most widely-used e-mail encryption standard in the world. It
is defined by the OpenPGP Working Group of the Internet Engineering Task
Force (IETF) Proposed Standard RFC 4880. The OpenPGP standard was originally
derived from PGP (Pretty Good Privacy), first created by Phil Zimmermann in
1991.

* <http://tools.ietf.org/html/rfc4880>
* <http://www.openpgp.org/>

Features
--------

* Encodes and decodes ASCII-armored OpenPGP messages.
* Parses OpenPGP messages into their constituent packets.
  * Supports both old-format (PGP 2.6.x) and new-format (RFC 4880) packets.
* Includes a GnuPG wrapper for features that are not natively supported.

Examples
--------

    require 'openpgp'

### Decoding an ASCII-armored message

    require 'open-uri'
    text = open('http://ar.to/pgp.txt').read

    msg = OpenPGP::Message.parse(OpenPGP.dearmor(text))

### Generating a new keypair

    gpg = OpenPGP::Engine::GnuPG.new(:homedir => '~/.gnupg')
    key_id = gpg.gen_key({
      :key_type      => 'DSA',
      :key_length    => 1024,
      :subkey_type   => 'ELG-E',
      :subkey_length => 1024,
      :name          => 'J. Random Hacker',
      :comment       => nil,
      :email         => 'jhacker@example.org',
      :passphrase    => 'secret passphrase',
    })

Documentation
-------------

* <http://openpgp.rubyforge.org/>

Download
--------

To get a local working copy of the development repository, do:

    % git clone git://github.com/bendiken/openpgp.git

Alternatively, you can download the latest development version as a tarball
as follows:

    % wget http://github.com/bendiken/openpgp/tarball/master

Installation
------------

The recommended installation method is via RubyGems. To install the latest
official release from Gemcutter, do:

    % [sudo] gem install openpgp

Resources
---------

* <http://openpgp.rubyforge.org/>
* <http://github.com/bendiken/openpgp>
* <http://rubyforge.org/projects/openpgp>
* <http://raa.ruby-lang.org/project/openpgp/>
* <http://www.ohloh.net/p/openpgp>

Authors
-------

* [Arto Bendiken](mailto:arto.bendiken@gmail.com) - <http://ar.to/>
* [Kévin Lacointe](mailto:kevinlacointe@gmail.com)

License
-------

OpenPGP.rb is free and unencumbered public domain software. For more
information, see <http://unlicense.org/> or the accompanying UNLICENSE file.
