Implement pycrypto aes in lua.

Why do this?

I use pycrypto to encrypt with aes in client, and openresty lua-resty-string aes to decrypt in server.

And I cannot easily handle these, because the decrypt content is not the same as source. 
I known that may be I use lua-resty-string wrong, but I think the best way is to implement pycrypto aes in lua,
so I use pycrypto source and begin to integrate.