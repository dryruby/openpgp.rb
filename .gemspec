#!/usr/bin/env ruby -rubygems
# -*- encoding: utf-8 -*-

GEMSPEC = Gem::Specification.new do |gem|
  gem.version            = File.read('VERSION').chomp
  gem.date               = File.mtime('VERSION').strftime('%Y-%m-%d')

  gem.name               = 'openpgp'
  gem.homepage           = 'http://openpgp.rubyforge.org/'
  gem.license            = 'Public Domain' if gem.respond_to?(:license=)
  gem.summary            = 'A pure-Ruby implementation of the OpenPGP Message Format (RFC 4880).'
  gem.description        = <<-EOF
    OpenPGP.rb is a pure-Ruby implementation of the OpenPGP Message Format
    (RFC 4880), the most widely-used e-mail encryption standard in the world.
  EOF
  gem.rubyforge_project  = 'openpgp'

  gem.authors            = ['Arto Bendiken']
  gem.email              = 'arto.bendiken@gmail.com'

  gem.platform           = Gem::Platform::RUBY
  gem.files              = %w(AUTHORS CONTRIBUTORS README UNLICENSE VERSION bin/openpgp) + Dir.glob('lib/**/*.rb')
  gem.bindir             = %q(bin)
  gem.executables        = %w(openpgp)
  gem.default_executable = gem.executables.first
  gem.require_paths      = %w(lib)
  gem.extensions         = %w()
  gem.test_files         = %w()
  gem.has_rdoc           = false

  gem.required_ruby_version      = '>= 1.8.1'
  gem.requirements               = ['GnuPG >= 1.4.7 (not required, but enables extra functionality)']
  gem.add_development_dependency 'yard' , '>= 0.5.8'
  gem.add_development_dependency 'rspec', '>= 1.3.0'
  gem.add_runtime_dependency     'open4', '>= 1.0.1'
  gem.post_install_message       = nil
end
