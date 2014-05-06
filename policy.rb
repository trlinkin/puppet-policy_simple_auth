#! /opt/puppet/bin/ruby

require 'openssl'
require 'yaml'

pol_file = File.join(File.dirname(__FILE__),"auths.yaml")
if File.exists? pol_file
  pol = YAML.load(File.read(pol_file))
else
  puts "Cannot Open #{File.expand_path pol_file}"
  exit 1
end

unless pol[:id_oid]
  puts "No :id_oid found in the #{polfile}"
  exit 1
end

id_oid = pol[:id_oid]
pw = nil
id = nil
extentions = Hash.new
csr = OpenSSL::X509::Request.new STDIN.read

csr.attributes.each do |attr|
  pw = attr.value.first.value if attr.oid == 'challengePassword'

  if attr.oid == 'extReq'
    extraw = attr.value.first.value.map(&:value)

    index = -1
    extraw.map do |ext|
      index += 1

      ev = OpenSSL::X509::Extension.new(ext[0].value, ext[1].value)
      extentions[ev.oid] = ev.value
    end
  end
end

id = extentions[id_oid]
puts "Found in CSR: ID(#{id_oid}) '#{id}' and Challenge-Password '#{pw}'"

if pw && id
  if pol[id] && pol[id] == pw
    puts "Found Match"
    exit 0
  end
end
puts "No Match Found"
exit 1
