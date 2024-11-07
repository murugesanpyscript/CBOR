import sys
import base64
import json
import binascii
import os
import struct
import getpass
import datetime
import re
from optparse import OptionGroup, OptionParser
import socket
import warnings
import subprocess
import cbor2
from pycose.messages import Enc0Message
from pycose.keys import SymmetricKey
from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID, ContentType
from pycose.algorithms import Es384


try:
    import pwinput
except:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pwinput"], stdout=subprocess.DEVNULL)
        import pwinput

        print("Installed dependency \"pwinput\" successfully.")
    except Exception as e:
        print("Unable to install dependency: pwinput. Some error occured.\n")
        print("debug info:")
        print(e)
try:
    from Crypto.PublicKey import RSA
    from Crypto.PublicKey.RSA import construct
    from Crypto.PublicKey import RSA
    from Crypto.PublicKey import ECC
    from Crypto.Signature import pkcs1_15, pss
    from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
except:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"], stdout=subprocess.DEVNULL)
        from Crypto.PublicKey import RSA
        from Crypto.PublicKey.RSA import construct
        from Crypto.PublicKey import RSA
        from Crypto.PublicKey import ECC
        from Crypto.Signature import pkcs1_15, pss
        from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
        print("Installed dependency \"pycryptodome\" successfully.")
    except Exception as e:
        print("Unable to install dependency: pycryptodome. Some error occured.\n")
        print("debug info:")
        print(e)
warnings.filterwarnings('ignore')
from codecs import encode

try:
    import requests
except:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"], stdout=subprocess.DEVNULL)
        import requests
        print("Installed dependency \"requests\" successfully.")
    except Exception as e:
        print("Unable to install dependency: requests. Some error occured.\n")
        print("debug info:")
        print(e)
warnings.filterwarnings('ignore')

supported_hash_algs = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                       'sha-1', 'sha-224', 'sha-256', 'sha-384', 'sha-512']

supported_padding = ['pkcs1', 'pss']

mechanisms = {
    "pkcs1": 1,
    "pss": 13,
    "rsasha1": 6,
    "rsasha224": 70,
    "rsasha256": 64,
    "rsasha384": 65,
    "rsasha512": 66,
    "rsapsssha1": 14,
    "rsapsssha224": 71,
    "rsapsssha256": 67,
    "rsapsssha384": 68,
    "rsapsssha512": 69,
    "sha1": 544,
    "sha224": 597,
    "sha256": 592,
    "sha384": 608,
    "sha512": 624,
    "ecdsa": 4161,
    "ecdsasha384": 4165
}

mgf = {
    "sha1": 1,
    "sha224": 5,
    "sha256": 2,
    "sha384": 3,
    "sha512": 4
}

# ASN.1 DER encoded OID Hashing Algorithms per RFC 3447
sha1_asn1_prefix = '3021300906052b0e03021a05000414'
sha224_asn1_prefix = '302d300d06096086480165030402040500041c'
sha256_asn1_prefix = '3031300d060960864801650304020105000420'
sha384_asn1_prefix = '3041300d060960864801650304020205000430'
sha512_asn1_prefix = '3051300d060960864801650304020305000440'


venafi_url = "https://css.corp.nandps.com"
venafi_uat_url = "https://css-uat.corp.nandps.com"
venafi_uat_url_enclave = "http://10.99.56.11"
venafi_url_enclave = "http://10.99.56.10"

proxies = {
    'http': None,
    'https': None
}


def parse_args_sign(args=sys.argv[1:]):
    """ Parse the input CLI arguments to obtain all necessary variables
        from the user for sign, displaying an appropriate error message for any
        malformed or missing arguments.
    """

    op = OptionParser(usage=
                      "Usage: %prog sign -i FILE -k KEY-LABEL")
    op.add_option('-i', '--infile', dest='infile', type='string',
                  help='Path for the input file to sign')
    op.add_option('-r', '--reason', dest='reason', type='string',
                  help='Reason for this submision')
    op.add_option('-k', '--key', dest='label', type='string',
                  help='Specify the signing key label')
    op.add_option('-d', '--digestalgorithm', dest='dgstalg', type='string',
                  metavar='DGST', action='store', default='sha256',
                  help='Digest hash algorithm to use for signing [default: %default]')
    op.add_option('-p', '--padding', dest='padding', type='string',
                  metavar='PAD', action='store', default='pkcs1',
                  help='RSA padding algorithm to use [default: %default]')
    op.add_option('', '--overwrite', dest='overwrite', default=False, action='store_true',
                  help='Overwrite the output file if it exists [default %default]')
    op.add_option('', '--uat', dest='uat', default=False, action='store_true',
                  help='Utilize UAT environment for signing instead of PROD. Not using this flag will automatically connect to PROD')
    op.add_option('', '--enclave', dest='enclave', default=False, action='store_true',
                  help='Use --enclave option while running the signing script from enclave environment')
    op.add_option('-v', '--verbose', dest='verbose', default=False, action='store_true',
                  help='Display verbose information while processing [default: %default]')
    op.add_option('', '--username', dest='username', type='string',
                  help='Pass username as command line argument')
    op.add_option('', '--password', dest='password', type='string',
                  help='Pass password as command line argument')
    opts, args = op.parse_args(args)

    # Validate that an input file is provided and that it exists
    if opts.infile is None:
        op.error('infile must be specified')
    if not os.path.isfile(opts.infile):
        op.error("'%s' is not a file" % opts.infile)

    # Validate that an output file is provided and that it does not exist or the
    # overwrite flag is provided, allowing the file to be overwritten
    file_name_list = re.split("UNSIGNED.BIN", opts.infile, flags=re.IGNORECASE)
    file_name = ''.join(file_name_list[i] for i in range(0, len(file_name_list) - 1)) + "signed.bin"
    if os.path.isfile(file_name) and not opts.overwrite:
        op.error("'%s' already exists" % file_name)

    # Validate that the user has provided the key label so that we may
    # look up the key to use for signing
    if opts.label is None:
        op.error('key label must be specified')

    # Validate that the user provided a valid supported hashing algorithm
    if opts.dgstalg.lower() not in supported_hash_algs:
        op.error('invalid/unsupported digest hash algorithm, \'%s\'' % opts.dgstalg)
    else:
        opts.dgstalg = opts.dgstalg.lower()
        opts.dgstalg = opts.dgstalg.replace('-', '')

    """ Validate that the user provided a valid supported padding algorithm
    """
    if opts.padding.lower() not in supported_padding:
        op.error('invalid/unsupported padding algorithm, \'%s\'' % opts.padding)
    else:
        opts.padding = opts.padding.lower()

    """ Validate that if command line auth is used then
        both username and password are entered by the user
    """
    if opts.username is not None and opts.password is None:
        op.error("please provide the password using --password option")
    elif opts.username is None and opts.password is not None:
        op.error("please provide the username using --username option")

    return opts, args


def parse_args_listkeys(args=sys.argv[1:]):
    """ Parse the optional CLI arguments: username and password for
        listing all the available keys.
    """
    op = OptionParser()
    op.add_option('', '--username', dest='username', type='string',
                  help='Pass username as command line argument')
    op.add_option('', '--password', dest='password', type='string',
                  help='Pass password as command line argument')
    op.add_option('', '--uat', dest='uat', default=False, action='store_true',
                  help='Utilize UAT environment for signing instead of PROD. Not using this flag will automatically connect to PROD.')
    op.add_option('', '--enclave', dest='enclave', default=False, action='store_true',
                  help='Use --enclave option while running the signing script from enclave environment')
    op.add_option('-v', '--verbose', dest='verbose', default=False, action='store_true',
                  help='Display verbose information while processing [default: %default]')
    opts, args = op.parse_args(args)

    """ Validate that if command line auth is used then
        both username and password are entered by the user
    """
    if opts.username is not None and opts.password is None:
        op.error("please provide the password using --password option")
    elif opts.username is None and opts.password is not None:
        op.error("please provide the username using --username option")

    return opts, args


def parse_args_download_key(args=sys.argv[1:]):
    """ Parse the optional CLI arguments: username and password for
        downloading the public key.
    """
    op = OptionParser(usage=
                      "Usage: %prog downloadpublickey -o FILE -k KEY-LABEL")
    op.add_option('', '--username', dest='username', type='string',
                  help='Pass username as command line argument')
    op.add_option('', '--password', dest='password', type='string',
                  help='Pass password as command line argument')
    op.add_option('', '--uat', dest='uat', default=False, action='store_true',
                  help='Utilize UAT environment for signing instead of PROD. Not using this flag will automatically connect to PROD.')
    op.add_option('', '--enclave', dest='enclave', default=False, action='store_true',
                  help='Use --enclave option while running the signing script from enclave environment')
    op.add_option('-v', '--verbose', dest='verbose', default=False, action='store_true',
                  help='Display verbose information while processing [default: %default]')
    op.add_option('-o', '--outfile', dest='outfile', type='string',
                  help='Path for the input file to sign')
    op.add_option('-k', '--key', dest='label', type='string',
                  help='Specify the signing key label')
    opts, args = op.parse_args(args)

    # Validate that an output file path is provided
    if opts.outfile is None:
        op.error('outfile must be specified')

    """ Validate that the user has provided the key label so that we may
        look up the key to download """
    if opts.label is None:
        op.error('key label must be specified')

    """ Validate that if command line auth is used then
        both username and password are entered by the user
    """
    if opts.username is not None and opts.password is None:
        op.error("please provide the password using --password option")
    elif opts.username is None and opts.password is not None:
        op.error("please provide the username using --username option")

    return opts, args


def bytes_to_dwords(b):
    """ Convert a number of bytes to DWORDs. Because 1 DWORD = 4 Bytes
        this is performed by simply dividing the number of bytes by 4.
    """

    if b % 4 != 0:
        raise ValueError("Bytes provided to bytes_to_dwords() was not a multiple of 4")

    return b / 4


def byte_array_to_hex_str(b):
    """ Given a ByteArray, converts the ByteArray into a hexadecimal
        string of characters preceeded with '0x' for easy printing.
    """

    reversed = b[::-1]
    # Changed - addded str() typecasting and removed b'' markings
    return ('0x' + str(binascii.hexlify(bytearray(reversed))).lstrip("b'").rstrip("'"))


def int_to_hex_str(i):
    """ Given an integer value, converts the integer to a hexadecimal
        string of characters preceeded with '0x' for easy printing.
    """

    # Changed - added int() typecasting
    return ('0x' + format(int(i), '08x'))


def is_valid_bcd_date(d):
    """ Given a ByteArray that represents a BCD Date, determine if it
        is a valid date by attempting to parse it with the datetime
        library.
    """

    try:
        # year = binascii.hexlify(bytearray(d[3])) + binascii.hexlify(bytearray(d[2]))
        # month = binascii.hexlify(bytearray(d[1]))
        # day = binascii.hexlify(bytearray(d[0]))
        # Changed this as older implementation was not working

        year = str(hex(d[3])).lstrip('0x') + str(hex(d[2])).lstrip('0x')
        month = str(hex(d[1])).lstrip('0x')
        day = str(hex(d[0])).lstrip('0x')

        datetime.datetime.strptime(year + '-' + month + '-' + day, '%Y-%m-%d')
    except ValueError:
        return False
    return True


def validate_module(module, pub_len, sig_len, opts):
    """ Perform all required validation on the input module file to
        verify that it is a valid 0x06 type module.
    """

    # Providing a fixed header length, which is fixed length for most
    # ECSS modules.
    header_len = 0x80
    pubkey_len = pub_len
    exponent_len = 0x04
    signature_len = sig_len
    
    module_type_offset = 0x00
    module_type_length = 0x04
    expected_module_type = 0x00000006  # This defined module magic number is 0x06

    header_len_offset = module_type_offset + module_type_length
    header_len_length = 0x04
    expected_header_len = bytes_to_dwords(header_len + pubkey_len + exponent_len + signature_len)

    header_version_offset = header_len_offset + header_len_length
    header_version_length = 0x04
    expected_header_version = 0x00010000  # The header version 0x0001 is the RSA header version

    module_id_offset = header_version_offset + header_version_length
    module_id_length = 0x04

    module_vendor_offset = module_id_offset + module_id_length
    module_vendor_length = 0x04
    module_vendor_mask = 0x0000FFFF
    expected_module_vendor = 0x8086

    date_offset = module_vendor_offset + module_vendor_length
    date_length = 0x04

    size_offset = date_offset + date_length
    size_length = 0x04
    expected_size = bytes_to_dwords(len(module))  # The size should be the module size in DWORDs

    modulus_size_offset = size_offset + size_length
    modulus_size_length = 0x04
    expected_modulus_size = bytes_to_dwords(pubkey_len)

    sig_size_offset = modulus_size_offset + modulus_size_length
    sig_size_length = 0x04
    expected_sig_size = bytes_to_dwords(signature_len)

    exp_size_offset = sig_size_offset + sig_size_length
    exp_size_length = 0x04
    expected_exp_size = 0x01

    # Verify that the input module is at least as long as the fields that we're checking to prevent reading
    # off the end of the buffer.
    if len(module) < header_len + pubkey_len + signature_len:
        raise Exception("Module length (%d bytes) is smaller than the header length (%d bytes)" % (
        len(module), header_len + pubkey_len + signature_len))

    # Because the length computations (specifically the size field) are in DWORDs and not bytes, we must make
    # sure that the module as a whole aligns to a DWORD boundary, otherwise the length will be inaccurate.
    if len(module) % 4 != 0:
        raise Exception("Module length (%d bytes) did not align to the end of a DWORD" % len(module))

    # Verify that the module type matches the magic number we expect for this specific module format
    module_type = module[module_type_offset:module_type_offset + module_type_length]
    if struct.unpack('<I', bytearray(module_type))[0] != expected_module_type:
        raise Exception("Module type (%s) was not the expected module type (%s)" % (
        byte_array_to_hex_str(module_type), int_to_hex_str(expected_module_type)))

    # Verify that the header length matches the length we expect for a key of this size
    header_len_value = module[header_len_offset:header_len_offset + header_len_length]
    if struct.unpack('<I', bytearray(header_len_value))[0] != expected_header_len:
        raise Exception("Module header length (%s) did not match the expected header length (%s)" % (
        byte_array_to_hex_str(header_len_value), int_to_hex_str(expected_header_len)))

    # Header Version
    header_version = module[header_version_offset: header_version_offset + header_version_length]
    if struct.unpack('<I', bytearray(header_version))[0] != expected_header_version:
        raise Exception("Module header version (%s) did not match the expected header version (%s)" % (
        byte_array_to_hex_str(header_version), int_to_hex_str(expected_header_version)))

    # The module ID would typically have the debug bit checked and only allow debug signing when the
    # debug bit is set and only allow release signing when the release bit is set. However since the
    # keys are no longer managed by the LTCSS system, there's no real difference between a "debug"
    # or a "release" key, thus there's nothing to check with the module ID field.
    # module_id = module[module_id_offset : module_id_offset + module_id_length]

    # Verify that the upper 2 bytes of the module vendor field (determined by the module_vendor_mask)
    # are the expected vendor values
    module_vendor = module[module_vendor_offset: module_vendor_offset + module_vendor_length]
    if struct.unpack('<I', bytearray(module_vendor))[
        0] & module_vendor_mask != expected_module_vendor & module_vendor_mask:
        raise Exception("Module vendor (%s) did not match the expected module vendor (%s)" % (
        byte_array_to_hex_str(module_vendor), int_to_hex_str(expected_module_vendor)))

    # Verify that the date supplied is a valid BCD format date (e.g. that it has the structure of
    # YYYYMMDD in hex)
    date = module[date_offset: date_offset + date_length]

    if not is_valid_bcd_date(date):
        raise Exception("Module date (%s) is not a valid date" % byte_array_to_hex_str(date))

    # Verify that the size field aligns to the expected size (e.g. that the size field is a DWORD
    # representation of the entire module size)
    size = module[size_offset: size_offset + size_length]

    if struct.unpack('<I', bytearray(size))[0] != expected_size:
        raise Exception("Module size (%s) did not match the expected size (%s)" % (
        byte_array_to_hex_str(size), int_to_hex_str(expected_size)))

    # Verify that the key size aligns to a DWORD representation of the public key
    modulus_size = module[modulus_size_offset: modulus_size_offset + modulus_size_length]
    if struct.unpack('<I', bytearray(modulus_size))[0] != expected_modulus_size:
        raise Exception("Modulus size (%s) did not align with the expected size (%s)" % (
        byte_array_to_hex_str(modulus_size), int_to_hex_str(expected_modulus_size)))

    # Verify that the x coordinate aligns to a DWORD representation of the signature
    sig_size = module[sig_size_offset: sig_size_offset + sig_size_length]
    if struct.unpack('<I', bytearray(sig_size))[0] != expected_sig_size:
        raise Exception("Signature size field (%s) did not align with the expected size (%s)" % (
        byte_array_to_hex_str(sig_size), int_to_hex_str(expected_sig_size)))

    # Verify that the exponent size aligns to a DWORD representation of the exponent
    exp_size = module[exp_size_offset: exp_size_offset + exp_size_length]
    if struct.unpack('<I', bytearray(exp_size))[0] != expected_exp_size:
        raise Exception("Exponent size field (%s) did not align with the expected size (%s)" % (
        byte_array_to_hex_str(exp_size), int_to_hex_str(expected_exp_size)))

    if opts.verbose:
        print("Validating module file structure - success\n")


def build_signable_object(module, public_key_length=0, signature_length=0):
    """ Extract the signable section of the module, giving us just the
        data that will be sent through hash/sign/verify operations.
    """

    # Using the fixed module header length
    header_len = 0x80
    pubkey_len = public_key_length
    #exponent_len = 0x04
    signature_len = signature_length

    signable_object = module[0:header_len]
    #signable_object += module[header_len + pubkey_len + exponent_len + signature_len:]
    signable_object += module[header_len + pubkey_len + signature_len:]

    return signable_object


def build_signable_hash(signable_object, opts):
    """ Given a ByteArray and CLI arguments (for determining the
        proper hash algorithm), this will generate a hash of the
        module for use in sign/verify operation.
    """

    if opts.dgstalg == 'sha1':
        hash = SHA1.new(signable_object)
        signable_hash = sha1_asn1_prefix + hash.hexdigest()

    elif opts.dgstalg == 'sha224':
        hash = SHA224.new(signable_object)
        signable_hash = sha224_asn1_prefix + hash.hexdigest()

    elif opts.dgstalg == 'sha256':
        hash = SHA256.new(signable_object)
        signable_hash = sha256_asn1_prefix + hash.hexdigest()

    elif opts.dgstalg == 'sha384':
        hash = SHA384.new(signable_object)
        signable_hash = sha384_asn1_prefix + hash.hexdigest()

    elif opts.dgstalg == 'sha512':
        hash = SHA512.new(signable_object)
        signable_hash = sha512_asn1_prefix + hash.hexdigest()

    if opts.verbose:
        print('hash for signing: ' + hash.hexdigest())
        print("digest: " + opts.dgstalg)
        print("signable hash: " + signable_hash + "\n")

    return signable_hash, hash


def get_venafi_token(username, password, opts):
    """ Issue a Venafi token to be used in API requests using
        key user's username and password
    """

    auth_request_url = venafi_url + "/vedauth/authorize/oauth"
    auth_request_body = {
        "client_id": "signing-script",
        "username": username,
        "password": password,
        "scope": "codesignclient"
    }

    auth_response = requests.post(auth_request_url, json=auth_request_body, verify=False, proxies=proxies)

    if opts.verbose:
        print("Getting Venafi OAuth token")

    if auth_response.status_code == 200:
        if opts.verbose:
            print("api call: " + auth_request_url)
            print("status code: " + str(auth_response.status_code) + "\n")
    else:
        try:
            auth_json_response = json.loads(auth_response.content)
            error = auth_json_response["error"]
            error_description = auth_json_response["error_description"]
            print("error: " + error + " - " + error_description + "\n")
            print("debug info:")
            print("api call: " + auth_request_url)
            print("status code: " + str(auth_response.status_code))
            print("response content: " + str(auth_json_response) + "\n")
        except Exception as e:
            print("Authentication Failed! Error making connection with Venafi.\n")
            print("debug info:")
            print("api call: " + auth_request_url)
            print("status code: " + str(auth_response.status_code))
            print(e)
        finally:
            raise SystemExit(1)

    auth_json_response = json.loads(auth_response.content)
    access_token = auth_json_response["access_token"]

    return access_token


def revoke_venafi_token(access_token):
    """ Revoke the Venafi token after signing is complete
    """
    revoke_request_url = venafi_url + "/vedauth/revoke/token"
    revoke_request_headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + access_token
    }

    revoke_response = requests.get(revoke_request_url, headers=revoke_request_headers, verify=False, proxies=proxies)

    if opts.verbose:
        print("Revoking Venafi token")

    if revoke_response.status_code == 200:
        if opts.verbose:
            print("api call: " + revoke_request_url)
            print("status code: " + str(revoke_response.status_code) + "\n")

    if revoke_response.status_code != 200:
        print("Token Revocation Failed!\n")
        print("debug info:")
        print("api call: " + revoke_request_url)
        print("status code: " + str(revoke_response.status_code))
        print("response content: " + str(revoke_response.content) + "\n")
        raise SystemExit(1)


def get_key_object(access_token, label, opts):
    """ Get the modulus and exponent of the key using
        the user provided key ID
    """

    get_object_url = venafi_url + "/vedhsm/API/GetObjects"
    get_object_request_headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + access_token
    }
    get_object_request_body = {
    }

    get_object_response = requests.post(get_object_url, json=get_object_request_body,
                                        headers=get_object_request_headers, verify=False, proxies=proxies)

    if opts.verbose:
        print("Getting the key objects available to logged in user")

    if get_object_response.status_code == 200:
        if opts.verbose:
            print("api call: " + get_object_url)
            print("status code: " + str(get_object_response.status_code) + "\n")

    else:
        print("Failed to get key objects! Unknown error occured.\n")
        print("debug info:")
        print("api call: " + get_object_url)
        print("status code: " + str(get_object_response.status_code))
        print("response content: " + str(get_object_response.content) + "\n")

        raise SystemExit(1)

    get_object_response_json = json.loads(get_object_response.content)

    modulus = ""
    exponent = ""
    key_id = ""

    if "PublicKeys" not in get_object_response_json:
        print("Object: " + get_object_response_json)
        print("Error! No keys associated with this account.\n")
        raise SystemExit(1)

    for public_key in get_object_response_json["PublicKeys"]:
        if public_key["Label"] == label:
            #modulus = base64.b64decode(public_key["Modulus"])
            #exponent = base64.b64decode(public_key["Exponent"])
            key_id = public_key["KeyId"]

            if opts.verbose:
                print("Public Key Found: " + str(public_key) + "\n")
                #print("Public key modulus returned by Venafi: " + public_key["Modulus"] + "\n")
                #print("Public Key exponent returned by Venafi: " + public_key["Exponent"] + "\n")
            break

#    if modulus == "" or exponent == "":
#        print("Key not found. Check if the provided key label is correct.\n")
#        raise SystemExit(1)

    return key_id


def submit_for_signing(access_token, signable_hash_base64, keyId, padding, dgst_algo):
    sign_request_url = venafi_url + "/vedhsm/API/Sign"

    sign_request_headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + access_token
    }

    # CBOR body for signing
    sign_request_body = {
        "ClientInfo": {
            "ClientLibraryName": "MyHSMClient",
            "ClientLibraryVersion": "1.0.0"
        },
        "ProcessInfo": {
            "Executable": opts.infile,
            "CommandLine": opts.reason,
            "Machine": socket.gethostname()
        },
        "KeyId": keyId,
        "Mechanism": 4165,
        "Data": signable_hash_base64
    }
        
    sign_response = requests.post(sign_request_url, json=sign_request_body, headers=sign_request_headers, verify=False, proxies=proxies)

    if opts.verbose:
        print("Submitted the file for signing\n")

    if sign_response.status_code == 200:
        if opts.verbose:
            print("api call: " + sign_request_url)
            print("status code: " + str(sign_response.status_code))
            print("request body: " + str(sign_request_body) + "\n")

    else:
        print("Signing Failed!\n")
        print("debug info:")
        print("api call: " + sign_request_url)
        print("status code: " + str(sign_response.status_code))
        print("request body: " + str(sign_request_body))
        print("response content: " + str(sign_response.content) + "\n")
        raise SystemExit(1)

    sign_json_response = json.loads(sign_response.content)
    signature = ""

    if "Success" in sign_json_response.keys() and sign_json_response["Success"] == True:
        if "ResultData" in sign_json_response.keys() and sign_json_response["ResultData"] != "":
            signature = base64.b64decode(sign_json_response["ResultData"])
            if opts.verbose:
                print("Complete response returned by Venafi: " + str(sign_json_response) + "\n")
                print("Signature returned by Venafi: " + sign_json_response["ResultData"] + "\n")
        else:
            print("Signing Failed! Signature not returned by the server.\n")

            print("debug info:")
            print("api call: " + sign_request_url)
            print("status code: " + str(sign_response.status_code))
            print("response content: " + str(sign_response.content) + "\n")
            raise SystemExit(1)

    elif "Error" in sign_json_response.keys():
        print("Signing Failed!")
        print(sign_json_response["Error"] + "\n")

        if sign_json_response[
            "Error"] == "Private Key Access: Your request was submitted for approval. Please wait for approval confirmation and retry.":
            raise SystemExit(10)
        elif sign_json_response["Error"] == "Private Key Access: Your request has been rejected.":
            raise SystemExit(11)
        else:
            raise SystemExit(1)

    return signature


def populate_signed_file(module, signature, signature_len, modulus_len):
    """ Given a signature and public key as returned by Venafi,
        populate them in the supplied module.
    """
    header_len = 0x80
    exponent_len = 0x04

    signed_object = bytearray(module[0:header_len])    
    signed_object += signature
    signed_object += module[header_len + modulus_len + exponent_len + signature_len:]

    return signed_object


def get_username_pass(opts):
    """Input the username and password from the user
       if not supplied as command line input"""

    if opts.username is not None and opts.password is not None:
        username = opts.username
        password = opts.password
    else:
        username = input("Enter Username: ")
        password = pwinput.pwinput(prompt="Enter Password: ")

    print("\n")
    return username, password


def create_public_key(modulus, exponent):
    # Convert modulus and exponent of public key to int to create the key
    modulus = int(encode(modulus, 'hex'), 16)
    exponent = int(encode(exponent, 'hex'), 16)

    if opts.verbose:
        print("Constructing the public key from modulus and exponent\n")

    # Create the key
    key = construct((modulus, exponent))
    pubKeyPEM = key.exportKey()
    pubKeyPEM = pubKeyPEM.decode('ascii')
    pubKeyPEM = ''.join(pubKeyPEM.splitlines()[1:-1])

    keyDER = base64.b64decode(pubKeyPEM)
    keyPub = RSA.importKey(keyDER)
    return keyPub


def verify(signature, hash):
    """ Verify if the signature returned from Venafi platform
        is correct
    """
    #keyPub = create_public_key(modulus, exponent)
    keyPub = ECC.generate(curve="p384")
    if(opts.verbose):
        print("Public Key: " + str(keyPub))
        print("Hash: " + str(hash) + "\n")
    
    

def signing_process(opts, username, password, venafi_url):
    # 1. Read the file
    file = open(opts.infile, "rb")
    module = file.read()
    file.close()

    # 2. Design COSE Structure - initialization
    #signer: {
    #    "name": "SK hynix",
    #    "uri": "https://css-uat.corp.nandps.com/Test-Cert-2.cer"
    #}
    signer: {
        0: "SK hynix",
        1: "https://css-uat.corp.nandps.com/Test-Cert-2.cer"
    }
    
    COSE_Sign1 = Sign1Message(
        phdr = {Algorithm: Es384, ContentType: 'application/corim-signed+cbor', 11: {0: "SK hynix",1: "https://css-uat.corp.nandps.com/Test-Cert-2.cer"}
    },
        uhdr = {},
        payload = module,
        signature = "jhasdfuiwretlna05asd5fds36"
    )
    
    # 3. Get Bearer access token from Venafi Auth API
    access_token = get_venafi_token(username, password, opts)
    if(opts.verbose):
        print("Access Token Found: " + access_token + "\n")

    try:
        key_id = get_key_object(access_token, opts.label, opts)
        
        # 4. Creates a signable hash of the data and encodes to base64
        if(opts.verbose):
            print("Payload: " + str(payload) + "\n")

        signable_hash, hash = build_signable_hash(payload, opts)
        signable_hash_base64 = base64.b64encode(bytes.fromhex(signable_hash)).decode()

        # 5. Submit the base64 hash of the signable file for signing
        # Permissions:  The caller must be a Key User.
        signature = submit_for_signing(access_token, signable_hash_base64, key_id, opts.padding, opts.dgstalg)
        if(opts.verbose):
            print("Signature: " + str(signature) + "\n")

        # 6. Encode the signature into the COSE structure
        COSE_Sign1.signature = signature
        encoded = COSE_Sign1.encode(sign=False)
        if opts.verbose:
            print("encoded message: " + str(type(encoded)) + "\n")
            print("encoded message: " + str(encoded) + "\n")

        # 7. Verify the signature
        #verify(signature, hash)

        # 8. Append signed data to input file
        # Encode CBOR object with signature
        signed_cbor_data = cbor2.dumps(cbor_file)

        try:
            # 9. Write signed CBOR data back to file
            with open("signed_data.cbor", "wb") as f:
                f.write(signed_cbor_data)
            if(opts.verbose):
                print("Signature added and written to file: signed_data.cbor\n")
                #print("Signed file created: " + file_name + "\n")
            print("Successfully Signed!\n")

        except Exception as e:
            print(
                "Error outputting the signed data to the provided output file! Please provide the correct path and a supported name.\n")
            print("debug info:")
            print(e)
            raise SystemExit(1)

    finally:
        revoke_venafi_token(access_token)


def get_all_keys(username, password, opts):
    """ Get the list of all keys available to the key user
    """
    access_token = get_venafi_token(username, password, opts)

    try:
        get_object_url = venafi_url + "/vedhsm/API/GetObjects"
        get_object_request_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + access_token
        }
        get_object_request_body = {
        }

        get_object_response = requests.post(get_object_url, json=get_object_request_body,
                                            headers=get_object_request_headers, verify=False, proxies=proxies)

        if opts.verbose:
            print("Getting the key objects available to logged in user")

        if get_object_response.status_code == 200:
            if opts.verbose:
                print("api call: " + get_object_url)
                print("status code: " + str(get_object_response.status_code) + "\n")

        else:
            print("Failed to get keys! Unknown error occured.\n")
            print("HEADERS: " + get_object_request_headers)
            print("BODY: " + get_object_request_body)
            print("debug info:")
            print("api call: " + get_object_url)
            print("status code: " + str(get_object_response.status_code))
            print("response content: " + str(get_object_response.content) + "\n")

            raise SystemExit(1)

        get_object_response_json = json.loads(get_object_response.content)
        print("HERE: " + str(get_object_response_json))

        if "PublicKeys" not in get_object_response_json:
            print("Error! No keys associated with this account.\n")
            raise SystemExit(1)

        keys = []
        for public_key in get_object_response_json["PublicKeys"]:
            if public_key["EnvironmentType"] == 4:
                keys.append(public_key["Label"])

        if keys == []:
            print("Error! No keys associated with this account.\n")
            raise SystemExit(1)

        print("Keys List:")
        for i, key in enumerate(keys):
            print(str(i + 1) + ") " + key)

        print("\n")
    finally:
        revoke_venafi_token(access_token)


def download_public_key(username, password, opts):
    access_token = get_venafi_token(username, password, opts)

    try:
        modulus, exponent, key_id = get_key_object(access_token, opts.label, opts)
        pubKey = create_public_key(modulus, exponent)
        file = open(opts.outfile, "wb")
        file.write(pubKey.exportKey())
        file.close()

        if opts.verbose:
            print("file path: " + opts.outfile)

        print("Public key file downloaded succesfully.\n")

    except Exception as e:
        print("Error downloading public key file")
        print(e)

    finally:
        revoke_venafi_token(access_token)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Error! No command provided.")
        print("Supported commands: sign, listkeys, downloadpublickey")
        sys.exit(1)

    # Code signing workflow
    if sys.argv[1] == "sign":
        opts, args = parse_args_sign()

        if opts.uat == True:
            if opts.enclave == True:
                venafi_url = venafi_uat_url_enclave
            else:
                venafi_url = venafi_uat_url
        elif opts.enclave == True:
            venafi_url = venafi_url_enclave

        username, password = get_username_pass(opts)
        signing_process(opts, username, password, venafi_url)


    # List all available keys workflow
    elif sys.argv[1] == "listkeys":
        opts, args = parse_args_listkeys()
        if opts.uat == True:
            if opts.enclave == True:
                venafi_url = venafi_uat_url_enclave
            else:
                venafi_url = venafi_uat_url
        elif opts.enclave == True:
            venafi_url = venafi_url_enclave
        username, password = get_username_pass(opts)
        get_all_keys(username, password, opts)

    elif sys.argv[1] == "downloadpublickey":
        opts, args = parse_args_download_key()
        if opts.uat == True:
            if opts.enclave == True:
                venafi_url = venafi_uat_url_enclave
            else:
                venafi_url = venafi_uat_url
        elif opts.enclave == True:
            venafi_url = venafi_url_enclave
        username, password = get_username_pass(opts)
        download_public_key(username, password, opts)

    else:
        print("Unsupported command: " + sys.argv[1])
        print("Supported commands: sign, listkeys, downloadpublickey")