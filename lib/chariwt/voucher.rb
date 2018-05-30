require "active_support/all"
require "cbor"
require 'ecdsa'

require 'cose/msg'

class DateTime
  def to_cbor(n = nil)
    to_time.to_cbor(n)
  end
end
class Date
  def to_cbor(n = nil)
    to_time.to_cbor(n)
  end
end

module Chariwt
  class Voucher
    cattr_accessor :debug
    attr_accessor :token_format

    attr_accessor :signing_cert
    attr_accessor :assertion, :createdOn, :voucherType
    attr_accessor :expiresOn, :serialNumber, :pinnedDomainCert
    attr_accessor :idevidIssuer, :domainCertRevocationChecks
    attr_accessor :lastRenewalDate, :priorSignedVoucherRequest
    attr_accessor :proximityRegistrarCert, :proximityRegistrarPublicKey
    attr_accessor :pinnedPublicKey
    attr_accessor :nonce
    attr_accessor :attributes
    attr_accessor :token
    attr_accessor :pubkey

    class RequestFailedValidation < Exception; end
    class MissingPublicKey < Exception; end
    class MalformedJSON < Exception; end
    class InvalidKeyType < Exception; end

    OBJECT_TOP_LEVEL = 'ietf-voucher:voucher'
    def self.object_top_level
      OBJECT_TOP_LEVEL
    end
    def object_top_level
      OBJECT_TOP_LEVEL
    end

    def self.decode_pem(pemstuff)
      return "" if pemstuff.blank?
      base64stuff = ""
      pemstuff.lines.each { |line|
        next if line =~ /^-----BEGIN CERTIFICATE-----/
        next if line =~ /^-----END CERTIFICATE-----/
        base64stuff += line
      }
      begin
        pkey_der = Base64.urlsafe_decode64(base64stuff)
      rescue ArgumentError
        pkey_der = Base64.decode64(base64stuff)
      end
    end

    def self.voucher_type
      :voucher
    end

    def self.cert_from_json1(json1)
      if data = json1["pinned-domain-cert"]
        pubkey_der = Base64.decode64(data)
        pubkey = OpenSSL::X509::Certificate.new(pubkey_der)
      end
    end

    def self.cert_from_json(json0)
      if json0[object_top_level]
        cert_from_json1(json0[object_top_level])
      else
        nil
      end
    end

    def self.object_from_verified_cbor(cbor1, pubkey)
      vr = new
      vr.voucherType = voucher_type
      vr.token_format= :cose_cbor
      vr.load_sid_attributes(cbor1)
      if pubkey
        vr.pubkey       = pubkey
        vr.signing_cert = pubkey
      end
      vr
    end

    def self.object_from_verified_json(json1, pubkey)
      vr = new
      vr.voucherType = voucher_type
      vr.load_attributes(json1)
      if pubkey
        vr.signing_cert = pubkey
      end
      vr
    end

    def self.json0_from_pkcs7(token)
      # first extract the public key so that it can be used to verify things.
      begin
        unverified_token = OpenSSL::PKCS7.new(token)
      rescue ArgumentError
        raise Voucher::RequestFailedValidation
      end

      certs = unverified_token.certificates
      certlist = []
      if certs
        sign0 = certs.try(:first)
        certlist = [sign0]
      end

      cert_store = OpenSSL::X509::Store.new
      # leave it empty!

      # the data will be checked, but the certificate will not be validates.
      unless unverified_token.verify(certlist, cert_store, nil, OpenSSL::PKCS7::NOCHAIN|OpenSSL::PKCS7::NOVERIFY)
        raise Voucher::RequestFailedValidation
      end

      json_txt = unverified_token.data
      return json_txt,unverified_token,sign0
    end

    def self.voucher_from_verified_data(json_txt, pubkey)
      json0 = JSON.parse(json_txt)
      json1 = json0[object_top_level]

      object_from_verified_json(json1, pubkey)
    end

    def self.from_pkcs7(token, anchor = nil)
      json_txt,unverified_token,sign0 = json0_from_pkcs7(token)
      json0 = JSON.parse(json_txt)
      pkey  = nil
      pubkey = cert_from_json(json0)
      raise Voucher::MissingPublicKey unless pubkey

      verified_token = OpenSSL::PKCS7.new(token)

      # leave it empty!
      cert_store = OpenSSL::X509::Store.new
      if anchor
        cert_store.add_cert(anchor)
        flags = OpenSSL::PKCS7::NOCHAIN
      else
        flags = OpenSSL::PKCS7::NOCHAIN|OpenSSL::PKCS7::NOVERIFY
      end

      unless unverified_token.verify([pubkey], cert_store, nil, flags)
        raise Voucher::RequestFailedValidation
      end
      # now univerified_token has passed second signature.
      voucher_from_verified_data(unverified_token.data, pubkey)
    end

    def self.from_pkcs7_withoutkey(token)
      json0,unverified_token,sign0 = json0_from_pkcs7(token)
      voucher_from_verified_data(json0, sign0)
    end

    def self.from_jose_json(token)
      # first extract the public key so that it can be used to verify things.
      begin
        unverified_token = JWT.decode token, nil, false
      rescue JWT::DecodeError
        # probably not a JWT object
        return nil
      end
      json0 = unverified_token[0]
      pkey  = nil
      pubkey = cert_from_json(json0)
      raise Voucher::MissingPublicKey unless pubkey

      begin
        decoded_token = JWT.decode token, pubkey.public_key, true, { :algorithm => 'ES256' }
      rescue
        return nil
      end

      json0 = unverified_token[0]
      pkey  = nil
      unless voucher=json0[object_top_level]
        raise Voucher::MalformedJSON
      end

      object_from_verified_json(voucher, pubkey)
    end

    def self.from_cose_cbor(token, pubkey = nil)
      # first extract the public key so that it can be used to verify things.
      unverified = Chariwt::CoseSign0.create(token)

      unverified.parse
      pubkey ||= unverified.pubkey

      # XXX something here if there is no key.
      begin
        valid = unverified.validate(pubkey)

      rescue Chariwt::CoseSign1::InvalidKeyType
        raise InvalidKeyType
      end

      raise Chariwt::RequestFailedValidation unless valid

      return object_from_verified_cbor(unverified, pubkey)
    end

    def initialize(options = Hash.new)
      # setup defaults to be pkcs/cms format.
      #  other options are:  cms_cbor
      #                and:  cose_cbor
      #
      options = {:format => :pkcs}.merge!(options)

      @token_format = options[:format]
      @attributes = Hash.new
      @voucherType = :unknown
    end

    def load_json(jhash)
      thing = jhash['ietf-voucher:voucher']
      load_attributes(thing)
    end
    def load_attributes(thing)
      #   +---- voucher
      #      +---- created-on?                      yang:date-and-time
      #      +---- expires-on?                      yang:date-and-time
      #      +---- assertion                        enumeration
      #      +---- serial-number                    string
      #      +---- idevid-issuer?                   binary
      #      +---- pinned-domain-cert?              binary
      #      +---- domain-cert-revocation-checks?   boolean
      #      +---- nonce?                           binary
      #      +---- last-renewal-date?               yang:date-and-time
      #      +---- prior-signed-voucher-request?    binary
      #      +---- proximity-registrar-cert?        binary

      # assignments are used whenever there are actually additional processing possible
      # for the assignment due to different formats.

      @attributes   = thing
      @nonce        = thing['nonce']
      self.assertion     = thing['assertion']
      @serialNumber = thing['serial-number']
      self.createdOn     = thing['created-on']
      self.expiresOn    = thing['expires-on']
      @idevidIssuer = thing['idevid-issuer']
      self.pinnedDomainCert = thing['pinned-domain-cert']
      @domainCertRevocationChecks = thing['domain-cert-revocation-checks']
      @lastRenewalDate  = thing['last-renewal-date']
      self.proximityRegistrarCert        = thing['proximity-registrar-cert']
      self.proximityRegistrarPublicKey   = thing['proximity-registrar-subject-public-key-info']

      self.priorSignedVoucherRequest_base64 = thing['prior-signed-voucher-request']
    end

    def yangsid2hash(contents)
      VoucherSID.yangsid2hash(contents)
    end

    def load_sid_attributes(cose1)
      #   +---- voucher
      #      +---- created-on?                      yang:date-and-time
      #      +---- expires-on?                      yang:date-and-time
      #      +---- assertion                        enumeration
      #      +---- serial-number                    string
      #      +---- idevid-issuer?                   binary
      #      +---- pinned-domain-cert?              binary
      #      +---- domain-cert-revocation-checks?   boolean
      #      +---- nonce?                           binary
      #      +---- last-renewal-date?               yang:date-and-time
      #      +---- prior-signed-voucher-request?    binary
      #      +---- proximity-registrar-cert?        binary

      # assignments are used whenever there are actually additional processing possible
      # for the assignment due to different formats.

      thing = yangsid2hash(cose1.contents)
      load_attributes(thing)
    end

    def generate_nonce
      @nonce = SecureRandom.urlsafe_base64
    end

    def update_attributes
      add_attr_unless_nil(@attributes, 'assertion',  @assertion)
      add_attr_unless_nil(@attributes, 'created-on', @createdOn)

      add_attr_unless_nil(@attributes, 'expires-on', @expiresOn)
      add_attr_unless_nil(@attributes, 'serial-number', @serialNumber)

      add_attr_unless_nil(@attributes, 'nonce', @nonce)
      add_attr_unless_nil(@attributes, 'idevid-issuer', @idevidIssuer)

      add_der_attr_unless_nil(@attributes,
                              'pinned-domain-cert', @pinnedDomainCert)

      case @pinnedPublicKey
      when ECDSA::Point
        add_attr_unless_nil(@attributes,
                            'pinned-domain-subject-public-key-info',
                            ECDSA::Format::PointOctetString.encode(@pinnedPublicKey, compression: true))

      else
        add_der_attr_unless_nil(@attributes,
                                'pinned-domain-subject-public-key-info',
                                @pinnedPublicKey)
      end

      case @pinnedPublicKey
      when ECDSA::Point
        add_attr_unless_nil(@attributes,
                            'pinned-domain-subject-public-key-info',
                            ECDSA::Format::PointOctetString.encode(@pinnedPublicKey, compression: true))

      else
        add_der_attr_unless_nil(@attributes,
                                'pinned-domain-subject-public-key-info',
                                @pinnedPublicKey)
      end

      add_attr_unless_nil(@attributes,
                          'domain-cert-revocation-checks',
                          @domainCertRevocationChecks)

      add_attr_unless_nil(@attributes, 'last-renewal-date', @lastRenewalDate)
      add_binary_attr_unless_nil(@attributes,
                                 'prior-signed-voucher-request',
                                 @priorSignedVoucherRequest)

      add_der_attr_unless_nil(@attributes,
                              'proximity-registrar-cert',
                              @proximityRegistrarCert)

      case @proximityRegistrarPublicKey
      when ECDSA::Point
        add_attr_unless_nil(@attributes,
                            'proximity-registrar-subject-public-key-info',
                            ECDSA::Format::PointOctetString.encode(@proximityRegistrarPublicKey, compression: true))

      else
        add_der_attr_unless_nil(@attributes,
                                'proximity-registrar-subject-public-key-info',
                                @proximityRegistrarPublicKey)
      end
    end

    def assertion=(x)
      if x
        @assertion = x.to_sym
      end
    end

    def createdOn=(x)
      if x
        if !x.is_a? String
          @createdOn = x
        else
          begin
            @createdOn = DateTime.parse(x)
            @voucherType = :time_based
          rescue ArgumentError
            @createdOn = nil
            nil
          end
        end
      end
    end

    def expiresOn=(x)
      if x
        if !x.is_a? String
          @expiresOn = x
        else
          begin
            @expiresOn = DateTime.parse(x)
            @voucherType = :time_based
          rescue ArgumentError
            @expiresOn = nil
            nil
          end
        end
      end
    end

    def pinnedDomainCert=(x)
      if x
        if x.is_a? OpenSSL::X509::Certificate
          @pinnedDomainCert = x
        elsif x.is_a? OpenSSL::PKey::PKey
          @pinnedDomainCert = x
        else
          begin
            @pinnedDomainCert = OpenSSL::X509::Certificate.new(x)
          rescue OpenSSL::X509::CertificateError
            decoded = Chariwt::Voucher.decode_pem(x)
            @pinnedDomainCert = OpenSSL::X509::Certificate.new(decoded)
          end
        end
      end
    end

    def decode_unknown_public_key(x)
      case x
      when OpenSSL::PKey::PKey
        x
      when ECDSA::Point
        # also a kind of public key
        x
      when String
        # try to decode it as a public key.
        begin
          OpenSSL::X509::Certificate.new(x)
        rescue OpenSSL::X509::CertificateError
          decoded = Chariwt::Voucher.decode_pem(x)
          OpenSSL::X509::Certificate.new(decoded)
        end
      else
        byebug if @@debug
        raise MissingPublicKey
        puts "Not sure what othe formats belong here"
      end
    end

    def pinnedPublicKey=(x)
      if x
        @pinnedPublicKey = decode_unknown_public_key(x)
      end
    end

    def proximityRegistrarCert=(x)
      if x
        @proximityRegistrarCert = decode_unknown_public_key(x)
      end
    end

    def proximityRegistrarPublicKey=(x)
      if x
        @proximityRegistrarPublicKey = decode_unknown_public_key(x).try(:public_key)
      end
    end

    def priorSignedVoucherRequest_base64=(x)
      if x
        self.priorSignedVoucherRequest = Base64.decode64(x)
      end
    end

    def load_file(io)
      json = JSON.parse(io.read)
      load_json(json)
      self
    end

    def json_voucher
      case voucherType
      when :time_based
      end

      vattr = Hash.new
      add_attr_unless_nil(vattr, 'assertion',  @assertion)
      add_attr_unless_nil(vattr, 'created-on', @createdOn)

      add_attr_unless_nil(vattr, 'expires-on', @expiresOn)
      add_attr_unless_nil(vattr, 'serial-number', @serialNumber)
      #add_base64_attr_unless_nil(vattr, 'idevid-issuer',  @idevidIssuer)
      add_der_attr_unless_nil(vattr, 'pinned-domain-cert', @pinnedDomainCert)
      add_base64_attr_unless_nil(vattr, 'pinned-public-key', @pinnedPublicKey)
      add_attr_unless_nil(vattr, 'nonce', @nonce)

      result = Hash.new
      result[object_top_level] = vattr
      result
    end

    def inner_attributes
      update_attributes
      attributes
    end

    def vrhash
      @vrhash ||= { object_top_level => inner_attributes }
    end

    def pkcs_sign(privkey, needcerts = true)
      flags = 0
      unless needcerts
        flags = OpenSSL::PKCS7::NOCERTS
      end
      digest = OpenSSL::Digest::SHA256.new
      smime  = OpenSSL::PKCS7.sign(signing_cert, privkey, vrhash.to_json, [], flags )
      @token = Base64.strict_encode64(smime.to_der)
    end

    #
    # CBOR routines
    #

    def hash2yangsid(vrhash)
      VoucherSID.hash2yangsid(vrhash)
    end

    # turns a voucher into an unsinged CBOR/YANG array based
    # upon the SID assignments
    def cbor_unsign
      @sidhash = hash2yangsid(vrhash)
      @token = @sidhash.to_cbor
    end

    def cose_sign(privkey, group = ECDSA::Group::Nistp256, temporary_key = nil)
      @sidhash = hash2yangsid(vrhash)
      sig = Chariwt::CoseSign1.new
      sig.content = @sidhash
      if pubkey
        sig.unprotected_bucket[Cose::Msg::VOUCHER_PUBKEY] = pubkey.to_wireformat
      end

      case privkey
      when OpenSSL::PKey::EC
        (privkey,group) = ECDSA::Format::PrivateKey.decode(privkey)

      # ECDSA private keys are just integers
      when Integer
        # nothing else to do.
      end

      @token = sig.generate_signature(group, privkey, temporary_key)

      @token
    end

    private
    def add_attr_unless_nil(hash, name, value)
      if value
        hash[name] = value
      end
    end

    def add_base64_attr_unless_nil(hash, name, value)
      unless value.blank?
        hash[name] = Base64.strict_encode64(value)
      end
    end

    def add_der_attr_unless_nil(hash, name, value)
      unless value.blank?
        case @token_format
        when :pkcs
          hash[name] = Base64.strict_encode64(value.to_der)
        when :cose_cbor, :cms_cbor
          hash[name] = value.to_der
        end
      end
    end

    def add_binary_attr_unless_nil(hash, name, value)
      unless value.blank?
        case @token_format
        when :pkcs
          hash[name] = Base64.strict_encode64(value)
        when :cose_cbor, :cms_cbor
          hash[name] = value
        end
      end
    end


  end
end
