require "active_support/all"
require 'date'
require 'json'
require 'openssl'
require 'ecdsa'
require 'byebug'
require 'jwt'
require 'chariwt'
require 'model/test_keys'

$NonceNumber = 1

RSpec.describe OpenSSL::X509::Store do
  include Testkeys

  it "should validate a certificate which is part of the cert store" do
    filen = "spec/files/voucher_request1.pkix"
    token = Base64.decode64(IO::read(filen))

    verified_token = OpenSSL::CMS::ContentInfo.new(token)
    flags = OpenSSL::CMS::NOINTERN
    cert_store = OpenSSL::X509::Store.new
    cert_store.add_cert(vr1_pubkey)

    result=cert_store.verify(vr1_pubkey)
    byebug
    expect(result).to be true
  end

end