#!/usr/bin/env ruby -rubygems
# -*- encoding: utf-8 -*-

GEMSPEC = Gem::Specification.new do |gem|
  gem.name               = 'openpgp'
  gem.version            = '0.0.1.3'
  gem.date               = '2009-04-30'
  gem.homepage           = 'http://github.com/bendiken/openpgp'
  gem.license            = 'Public Domain' if gem.respond_to?(:license=)
  gem.summary            = 'A pure-Ruby implementation of the OpenPGP Message Format (RFC 4880).'
  gem.description        = <<-EOF
    OpenPGP.rb is a pure-Ruby implementation of the OpenPGP Message Format (RFC 4880).
  EOF
  gem.rubyforge_project  = 'openpgp'

  gem.authors            = ['Arto Bendiken', 'Kévin Lacointe']
  gem.email              = 'arto.bendiken@gmail.com'

  gem.platform           = Gem::Platform::RUBY
  gem.files              = %w(UNLICENSE AUTHORS README README.rdoc Rakefile VERSION bin/openpgp) + Dir.glob('lib/**/*.rb')
  gem.files             -= %w(README.rdoc) # only for GitHub
  gem.bindir             = %q(bin)
  gem.executables        = %w(openpgp)
  gem.default_executable = gem.executables.first
  gem.require_paths      = %w(lib)
  gem.extensions         = %w()
  gem.test_files         = %w()
  gem.has_rdoc           = false

  gem.required_ruby_version  = '>= 1.8.2'
  gem.requirements           = ['GnuPG >= 1.4.7 (not required, but enables extra functionality)']
  gem.add_development_dependency 'rakefile'
  gem.post_install_message   = nil
end
