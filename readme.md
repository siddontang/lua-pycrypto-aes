Implement pycrypto aes in lua.

# Why do this?

I use pycrypto to encrypt with aes in client, and openresty lua-resty-string aes to decrypt in server.

And I cannot easily handle these, because the decrypt content is not the same as source. 
I known that may be I use lua-resty-string wrong, but I think the best way is to implement pycrypto aes in lua,
so I use pycrypto source and begin to integrate.

Now I have implemented aes mode ECB, CBC, CFB, OFB. I don't want to implement CTR mode because I found that writing pycrypto default counter is not easy. If you want to use CTR mode, you can implement yourself and supply a custom counter.

# Install

Very easy:

make  
make install

You may assign LUA_INCLUDE_DIR and LUA_LIB_DIR when make, default is for openresty with luajit. 

# Use

    require "pycrypto_aes"
    local aes = pycrypto_aes.new(key, pycrypto_aes.MODE_ECB)

    local cipher = aes:encrypt(plain)
    ngx.say(ngx.encode_base64(cipher))

    ngx.say(aes:decrypt(cipher))

# Feedback

If you found any bug, please contact me. Thank you very much!