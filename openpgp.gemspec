# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{openpgp}
  s.version = "0.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Arto Bendiken"]
  s.date = %q{2009-04-16}
  s.default_executable = %q{pgpdump}
  s.description = %q{OpenPGP.rb is a pure-Ruby implementation of the OpenPGP Message Format (RFC 4880).}
  s.email = %q{arto.bendiken@gmail.com}
  s.executables = ["pgpdump"]
  s.extra_rdoc_files = [
    "LICENSE",
    "README"
  ]
  s.files = [
    "LICENSE",
    "README",
    "Rakefile",
    "VERSION",
    "bin/pgpdump",
    "lib/openpgp.rb",
    "lib/openpgp/armor.rb",
    "lib/openpgp/message.rb",
    "lib/openpgp/packet.rb",
    "lib/openpgp/version.rb"
  ]
  s.has_rdoc = true
  s.homepage = %q{http://github.com/bendiken/openpgp}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.2}
  s.summary = %q{A pure-Ruby implementation of the OpenPGP Message Format (RFC 4880).}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
