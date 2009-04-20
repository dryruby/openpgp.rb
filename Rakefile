#!/usr/bin/env ruby
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'lib')))
require 'rubygems'
require 'rakefile' # http://github.com/bendiken/rakefile
require 'openpgp'

desc "Generate YARD documentation (with title)"
task :yardocs => :yardoc do
  # FIXME: fork YARD and patch it to allow the title to be configured
  sh "sed -i 's/YARD Documentation/OpenPGP.rb Documentation/' doc/yard/index.html"

  # TODO: investigate why YARD doesn't auto-link URLs like RDoc does
  html = File.read(file = 'doc/yard/readme.html')
  html.gsub!(/>(http:\/\/)([\w\d\.\/\-]+)/, '><a href="\1\2" target="_blank">\2</a>')
  html.gsub!(/(http:\/\/ar\.to\/[\w\d\.\/]+)/, '<a href="\1">\1</a>')
  html.gsub!(/(http:\/\/ar\.to)([^\/]+)/, '<a href="\1" target="_top">ar.to</a>\2')
  html.gsub!(/(mailto:[^\)]+)/, '<a href="\1">\1</a>')
  File.open(file, 'wb') { |f| f.puts html }
end
