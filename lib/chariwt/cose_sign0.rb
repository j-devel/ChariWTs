#
# this class presents a COSE (RFCXXXX) signature object in the abstract,
# it examines the CBOR and returns either a CoseSign or CoseSign1 object.
#
# Initialize with the binary data, and then when ready, call parse.
#

module Chariwt
  class CoseSign0
    attr_accessor :binary, :sha256, :digest
    attr_accessor :parsed, :validated, :valid, :signature, :signature_bytes
    attr_accessor :protected_bucket, :encoded_protected_bucket
    attr_accessor :unprotected_bucket, :content

    def self.create(string)
      create_io(StringIO.new(string))
    end

    def self.create_io(binary)
      thing = nil
      unpacker = CBOR::Unpacker.new(binary)
      # takes the first item, there should be only one...
      # unpacker does not take "first"
      unpacker.each { |req|
        thing = req   unless thing
      }

      # could be there was no data at all!
      # maybe should raise an exception.
      return nil unless thing

      klass = case thing.tag
      when 18
        CoseSign1
      when 98
        CoseSign
      end

      return klass.new(thing)
    end
  end
end

