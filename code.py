import base64
import time
import struct
import hashlib, hmac
import base64
import random
import string


period = 30  # interval between two generated keys
length = 6  # length of OTP


def timestamp():  # Returns the integer timestamp
    return int(round(time.time() / period))


# Accepts binary format of secret key and timestamp
# Returns OTP generated via hmac, Encryption used sha1
def otp(key, time):
    bin_counter = struct.pack('!L', 0) + struct.pack('!L',
                                                     time)  # Using Pack function from time interval 0 to the current time
    digest = hmac.new(key, bin_counter, hashlib.sha1)
    result = str(truncate(digest.digest())).ljust(length, '0')
    return result


def truncate(hash):  # Truncate the hash generated value
    offset = (hash[19]) & 0xf;
    # Algorithm from RFC
    return (
                   (((hash[offset + 0]) & 0x7f) << 24) |
                   (((hash[offset + 1]) & 0xff) << 16) |
                   (((hash[offset + 2]) & 0xff) << 8) |
                   ((hash[offset + 3]) & 0xff)
           ) % pow(10, length)


# Verifys a user inputted key against the current timestamp. Checks window within + or -4 to accept clock sync or delay in user entering otp.
# Accepts secret key, Otp generated via google and window duration
# loop over -window to +window and verify that google otp matches with the generated otp
# return true/false based on success
def validate(b32secretKey, userOTP, window=4):
    timeStampInInt = timestamp()
    # decoding secret key to base32
    binarySeed = base64.b32decode(b32secretKey)
    timestampRange = range(timeStampInInt - window, timeStampInInt + window)
    for ts in timestampRange:
        o = otp(binarySeed, ts)
        if int(o) == int(userOTP):
            return True
    return False


def qrCodeURL(site,
        secretKey):  # Using standard goggle api to generate QR code which will be then used by google authenticator app
    #return "http://chart.apis.google.com/chart?cht=qr&chs=300x300&chl=otpauth://totp/Sandesh?secret=" + secretKey + "&chld=H|0"
    return "http://chart.apis.google.com/chart?cht=qr&chs=300x300&chl=otpauth://totp/"+site+"?secret="+secretKey+"&chld=H|0"


# This is for testing only
def test():
    hash = generate_16char_base32(pre).decode()
    YOUR_SECRET_INITIAL_KEY = hash  #must be at least 16 base 32 characters, keep this secret
    site = input("enter your email")
    print(qrCodeURL(site, YOUR_SECRET_INITIAL_KEY))
    userOTP = input("Enter OTP: ")
    success = validate(YOUR_SECRET_INITIAL_KEY, int(userOTP), 4)
    if success:
        print("Successfully Authenticated by Google Authenticator")
    else:
        print("Authentication Failed")



def randomString(stringLength):
    """Generate a random string with the combination of lowercase and uppercase letters """
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(stringLength))

def generate_16char_base32(pre):

    prefix = str(pre).encode()
    prefix_len = len(prefix)
    if prefix_len > 10:
        return None
    remaining = 10 - prefix_len
    random_int_str = ''
    if remaining != 0:
        random_from = 10 ** (remaining - 1)
        random_to = (10 ** remaining) - 1
        random_int = random.randint(random_from, random_to)
        random_int_str = str(random_int).encode()
    str_to_encode = prefix + random_int_str
    encoded_str = base64.b32encode(str_to_encode)
    return encoded_str

pre = randomString(8)
#generate_16char_base32(pre)
test()
