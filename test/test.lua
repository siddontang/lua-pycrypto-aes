local key = "1111111111111111"
local iv = "1111111111111111"
local plain = "2222222222222222"

-- test ecb
AES = require "pycrypto_aes"
mime = require "mime"

local testfunc = function(key, mode, iv)
    local aes = AEFS.new(key, mode, iv)
    local cipher = mime.b64(aes:encrypt(plain))
    print(cipher)

    local enc = mime.unb64(cipher)
    aes = AES.new(key, mode, iv)
    print(aes:decrypt(enc))
end

testfunc(key, AES.MODE_CBC, iv)
