require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "openpgp"
    gem.summary = "A pure-Ruby implementation of the OpenPGP Message Format (RFC 4880)."
    gem.email = "arto.bendiken@gmail.com"
    gem.homepage = "http://github.com/bendiken/openpgp"
    gem.description = "OpenPGP.rb is a pure-Ruby implementation of the OpenPGP Message Format (RFC 4880)."
    gem.authors = ["Arto Bendiken"]
    gem.executables = ['pgpdump']
  end
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install bendiken-jeweler -s http://gems.github.com"
end

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

task :default => :test

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION').chomp : ''

  rdoc.rdoc_dir = 'doc/rdoc'
  rdoc.title = "OpenPGP #{version}"
  rdoc.rdoc_files.include('README*', 'LICENSE')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
