
#include <assert.h>
#include <string.h>
#include <math.h>
#include <lua.h>
#include <lauxlib.h>

#include "aes.h"

static int MODE_ECB = 1;
static int MODE_CBC = 2;
static int MODE_CFB = 2;
static int MODE_PGP = 4;
static int MODE_OFB = 5;
static int MODE_CTR = 6;
static int MODE_OPENPGP = 7;


static int create(lua_State* pState)
{
    int mode;

    int top = lua_gettop(pState);
    int keyLen = 0;
    const char* key = NULL;    
    block_state* pBlock = NULL;

    if (top > 1)
    {
        //check mode 
        mode = (int)lua_tonumber(pState, 2);
	if(mode != MODE_ECB)
	{
             luaL_error(pState, "Not Support AES Mode");
             return 0;
        }
    }

    key = lua_tolstring(pState, 1, &keyLen);
    switch(keyLen) {
        case 16:
        case 24:
        case 32:
            break;
        default:
            luaL_error(pState, "AES key must be either 16, 24, or 32 bytes long");
            return 0;
    }

    pBlock = (block_state*)lua_newuserdata(pState, sizeof(block_state));
    luaL_getmetatable(pState, "pycrypto_aes_mt");
    lua_setmetatable(pState, -2);

    if(block_init(pBlock, key, keyLen) != 0)
    {
        luaL_error(pState, "init aes object error");
        return 0;
    }

    return 1;
}

static int _crypto(lua_State* pState, void (*func)(block_state *self, unsigned char *in, unsigned char *out))
{
    block_state* pBlock = (block_state*)lua_touserdata(pState, 1);

    int dataLen = 0;
    const char* data = NULL;
    char* buffer = NULL;

    data = lua_tolstring(pState, 2, &dataLen);
    if (dataLen & 0x0000000F)
    {   
        luaL_error(pState, "Input strings must be a multiple of 16 in length");
        return 0;
    }

    buffer = (char*)malloc(dataLen);
    if (!buffer)
    {
        luaL_error(pState, "alloc memory error");
        return 0;
    }

    func(pBlock, data, buffer);

    lua_pushlstring(pState, buffer, dataLen);
    free(buffer);
    return 1;

}


static int encrypt(lua_State* pState)
{
    return _crypto(pState, block_encrypt);
}

static int decrypt(lua_State* pState)
{
    return _crypto(pState, block_decrypt);
}


#define regMode(pState, mode) registerMode(pState, mode, #mode)


void registerMode(lua_State* pState, int mode, const char* name)
{
    lua_pushnumber(pState, mode);
    lua_setfield(pState, -2, name);
}

int luaopen_pycrypto_aes(lua_State *pState)
{
    luaL_Reg reg[] = {
        {"new", create},
        {NULL, NULL}
    };


    luaL_Reg regMeta[] = {
        {"encrypt", encrypt},
        {"decrypt", decrypt},
        {NULL, NULL}
    };

    luaL_newmetatable(pState, "pycrypto_aes_mt");
    lua_pushvalue(pState, -1);
    lua_setfield(pState, -2, "__index");
    luaL_register(pState, NULL, regMeta);

    luaL_register(pState, "pycrypto_aes", reg);

    lua_pushliteral(pState, VERSION);
    lua_setfield(pState, -2, "version");

    regMode(pState, MODE_ECB);
    regMode(pState, MODE_CBC);
    regMode(pState, MODE_CFB);
    regMode(pState, MODE_PGP);
    regMode(pState, MODE_OFB);
    regMode(pState, MODE_CTR);
    regMode(pState, MODE_OPENPGP);

    return 1;
}

/* vi:ai et sw=4 ts=4:
 */
