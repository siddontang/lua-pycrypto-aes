from Crypto.Cipher import AES
import base64

iv = '1' * 16

class AESCipher:
    def __init__( self, key, mode ):
        self.key = key 
        self.mode = mode

    def encrypt( self, raw ):
        cipher = AES.new( self.key, self.mode, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, self.mode, iv )
        return cipher.decrypt( enc[16:] )


if __name__ == '__main__':
    key = '1' * 16
    plain = '2' * 16

    aes = AES.new(key)
    cipher = aes.encrypt(plain)
    print cipher.encode('base64')
    print aes.decrypt(cipher)

    mode = AES.MODE_CBC
    aes = AESCipher(key, mode)
    cipher = aes.encrypt(plain)
    print cipher
    print aes.decrypt(cipher)

    mode = AES.MODE_CFB
    aes = AESCipher(key, mode)
    cipher = aes.encrypt(plain)
    print cipher
    print aes.decrypt(cipher)

    mode = AES.MODE_OFB
    aes = AESCipher(key, mode)
    cipher = aes.encrypt(plain)
    print cipher
    print aes.decrypt(cipher)
