# Google-Authenticator-for-Python

Google Authenticator implements two-step verification services using the Time-based One-time Password Algorithm and HMAC-based One-time Password algorithm.
Four library functions are imported in this program.
1. base64 for data encoding and decoding.
2. time for current time
3. struct for pack function
4. hashlib and hmac for message authentication

Two variables are used period for the time interval between two keys and length denotes the length of otp.

Timestamp round time to nearest time by dividing by 30 i.e period.

In otp function bin_counter calculates the packed binary data from time interval 0 to the current time. Digest sends the value to the hmac function which returns a new hmac msg.
the answer is truncated and left justified.

The truncate function takes the has value and calculate the offset value which is the last 4 bits of hash[19].The hash[19] means 19th byte of the string
After that, we concatenate the bytes from hash[offset] to hash[offset+3] and return them. 
Finally, using a simple modulo operation, we obtain the one time password that’s a reasonable length.The algorithm implemented is RFC. 


Validate function Verifys a user inputted key against the current timestamp. Checks window within + or -4 to accept clock sync or delay in user entering otp.
It converts timestamp to an integer value. The binaryseed variable decodes the value of the secret key using base64decode function.
The range of the timestamp varies between + and - 4 and it accepts the otp within this timeframe.
Then for all the values in timestamprange we iterate and the otp is calculated. The entered otp is verified with the calculated otp.
If it is correct it returns true else false.

The QRCodeURL uses a Google API to generate a QR Code which contains the secret key and can be scanned by Google AUthenticator APP.

The test function tests the program. The initial secret key is given which is passed to qrcodeurl which produces a QR Code.
Then the userOTP takes the input from the user and passes to the validate function. Upon success it prints successfully
authenticated else authentication failed.


References:

https://medium.freecodecamp.org/how-time-based-one-time-passwords-work-and-why-you-should-use-them-in-your-app-fdd2b9ed43c3
https://stackoverflow.com/questions/8529265/google-authenticator-implementation-in-python
https://medium.com/@tilaklodha/google-authenticator-and-how-it-works-2933a4ece8c2
https://tools.ietf.org/html/rfc4226 #RFC ALgorithm	
