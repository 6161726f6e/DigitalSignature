from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15

# using RSA 2048b key here, which is FIPS-compliant for digital signatures
# Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

# pycrypto references
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html?highlight=sign#Crypto.Signature.pkcs1_15.PKCS115_SigScheme.sign

def generateKeys():
# function to generate RSA key pair and store it
	key = RSA.generate(2048)
	private_key = key.export_key()
	file_out = open("./key/test-private.pem", "wb")
	file_out.write(private_key)
	file_out.close()

	public_key = key.publickey().export_key()
	file_out = open("./key/test-public.pem", "wb")
	file_out.write(public_key)
	file_out.close()

def verifySignature(data, pubKey, sig):
# function to verify the data integrity
	msgHash = SHA512.new(data)
	try:
	    pkcs1_15.new(pubKey).verify(msgHash, sig)
	    print("The signature for ", data, "is valid.")
	except (ValueError, TypeError):
	    print("The signature for ", data, "is not valid.")

#######################################################################
## Generates key pair (1-time only) ###################################
# generateKeys()

## Now, provider can read in and use the key #########################
privateKey = RSA.import_key(open("./key/test-private.pem").read())

msgOriginal = b'test legitimate data'	# sample legitimate data

# gen sha512 hash of original data
msgHash = SHA512.new(msgOriginal)
# generate digital signature for Original Data (msgOriginal)
signature = pkcs1_15.new(privateKey).sign(msgHash)

#######################################################################
## Now, can verify the data ############################
# NOTE: provider would share public key verifying party
# NOTE: provider saves signature of data with the data

publicKey = RSA.import_key(open('./key/test-private.pem').read())

msgTampered = b'test bad actor data'   # sample illegitimate data

# Verify that the original data matches digital signature
verifySignature(msgOriginal, publicKey, signature)

# Verify that the tampered data doesn't match digital signature
verifySignature(msgTampered, publicKey, signature)
