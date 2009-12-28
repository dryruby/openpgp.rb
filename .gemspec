#!/usr/bin/env ruby -rubygems
# -*- encoding: utf-8 -*-

GEMSPEC = Gem::Specification.new do |gem|
  gem.name               = 'openpgp'
  gem.version            = '0.0.2.1'
  gem.date               = '2009-12-20'
  gem.homepage           = 'http://openpgp.rubyforge.org/'
  gem.license            = 'Public Domain' if gem.respond_to?(:license=)
  gem.summary            = 'A pure-Ruby implementation of the OpenPGP Message Format (RFC 4880).'
  gem.description        = <<-EOF
    OpenPGP.rb is a pure-Ruby implementation of the OpenPGP Message Format
    (RFC 4880), the most widely-used e-mail encryption standard in the world.
  EOF
  gem.rubyforge_project  = 'openpgp'

  gem.authors            = ['Arto Bendiken', 'Kévin Lacointe']
  gem.email              = 'arto.bendiken@gmail.com'

  gem.platform           = Gem::Platform::RUBY
  gem.files              = %w(AUTHORS README README.md Rakefile UNLICENSE VERSION bin/openpgp) + Dir.glob('lib/**/*.rb')
  gem.files             -= %w(README.md) # only for GitHub
  gem.bindir             = %q(bin)
  gem.executables        = %w(openpgp)
  gem.default_executable = gem.executables.first
  gem.require_paths      = %w(lib)
  gem.extensions         = %w()
  gem.test_files         = %w()
  gem.has_rdoc           = false

  gem.required_ruby_version      = '>= 1.8.2'
  gem.requirements               = ['GnuPG >= 1.4.7 (not required, but enables extra functionality)']
  gem.add_development_dependency 'rspec', '>= 1.2.9'
  gem.add_development_dependency 'yard' , '>= 0.5.2'
  gem.add_runtime_dependency     'open4', '>= 1.0.1'
  gem.post_install_message       = nil
end
