
#include <assert.h>
#include <string.h>
#include <math.h>
#include <lua.h>
#include <lauxlib.h>

#include "aes.h"

#define MODE_ECB 1
#define MODE_CBC 2
#define MODE_CFB 3
#define MODE_OFB 5
#define MODE_CTR 6

static int pycrypto_aes_key;

typedef struct 
{
    int mode;
    int count;
    int segment_size;
    unsigned char IV[BLOCK_SIZE];
    unsigned char oldCipher[BLOCK_SIZE];
    block_state st;
} AESObject;

static int create(lua_State* pState)
{
    int mode = MODE_ECB;

    int top = lua_gettop(pState);
    int keyLen = 0;
    int IVLen = 0;
    int segment_size = 0;
    const char* key = NULL; 
    const char* IV = NULL;   
    AESObject* aes = NULL;

    key = luaL_checklstring(pState, 1, &keyLen);
    switch(keyLen) 
    {
        case 16:
        case 24:
        case 32:
            break;
        default:
            luaL_error(pState, "AES key must be either 16, 24, or 32 bytes long");
            return 0;
    }

    if (top > 1)
    {
        //check mode
        mode = luaL_checkint(pState, 2);
    }

    if (top > 2)
    {
        //check iv
        IV = luaL_checklstring(pState, 3, &IVLen);
    }

    if (top > 3)
    {
        //check segment size
        segment_size = luaL_checkint(pState, 4);
    }

    switch(mode)
    {
        case MODE_ECB:
        case MODE_CBC:
        case MODE_CFB:
        case MODE_OFB:
            break;
        default:
            luaL_error(pState, "Not Support AES Mode");
            return 0;
    }

    if (IVLen != BLOCK_SIZE && mode != MODE_ECB && mode != MODE_CTR)
    {
        luaL_error(pState, "IV must be %i bytes long", BLOCK_SIZE);
        return 0;
    }

    if (mode == MODE_CFB) 
    {
        if (segment_size == 0) 
            segment_size = 8;
        
        if (segment_size < 1 || segment_size > BLOCK_SIZE*8 
            || ((segment_size & 7) != 0)) 
        {
            luaL_error(pState,  "segment_size must be multiple of 8 (bits) between 1 and %i", BLOCK_SIZE*8);
            return 0;
        }
    }

    aes = (AESObject*)lua_newuserdata(pState, sizeof(AESObject));
    aes->mode = mode;
    aes->segment_size = segment_size;
    aes->count = BLOCK_SIZE;

    memset(aes->IV, 0, BLOCK_SIZE);
    memset(aes->oldCipher, 0, BLOCK_SIZE);
    memcpy(aes->IV, IV, IVLen);

    lua_pushlightuserdata(pState, &pycrypto_aes_key);
    lua_gettable(pState, LUA_REGISTRYINDEX);

    lua_setmetatable(pState, -2);

    if(block_init(&(aes->st), key, keyLen) != 0)
    {
        luaL_error(pState, "init aes object error");
        return 0;
    }

    return 1;
}

static int encrypt(lua_State* pState)
{
    AESObject* aes = (AESObject*)lua_touserdata(pState, 1);

    unsigned char *buffer, *str;
    unsigned char temp[BLOCK_SIZE];
    int i, j, len;

    str = (unsigned char *)lua_tolstring(pState, 2, &len);
    if (len == 0)
    {
        lua_pushstring(pState, "");
        return 1;
    }

    if ( (len % BLOCK_SIZE) !=0 && 
         (aes->mode!=MODE_CFB) &&
         (aes->mode!=MODE_CTR))
    {
        luaL_error(pState, 
                 "Input strings must be "
                 "a multiple of %i in length",
                 BLOCK_SIZE);
        return 0;
    }
    if (aes->mode == MODE_CFB && 
        (len % (aes->segment_size/8) !=0)) {
        luaL_error(pState, 
                 "Input strings must be a multiple of "
                 "the segment size %i in length",
                 aes->segment_size/8);
        return 0;
    }

    buffer = (char*)malloc(len);
    if (!buffer)
    {
        luaL_error(pState, "alloc memory error");
        return 0;
    }

    switch(aes->mode)
    {
        case(MODE_ECB):      
            for(i=0; i<len; i+=BLOCK_SIZE) 
            {
                block_encrypt(&(aes->st), str+i, buffer+i);
            }
            break;

        case(MODE_CBC):      
            for(i=0; i<len; i+=BLOCK_SIZE) 
            {
                for(j=0; j<BLOCK_SIZE; j++)
                {
                    temp[j]=str[i+j]^aes->IV[j];
                }
                block_encrypt(&(aes->st), temp, buffer+i);
                memcpy(aes->IV, buffer+i, BLOCK_SIZE);
            }
            break;

        case(MODE_CFB):      
            for(i=0; i<len; i+=aes->segment_size/8) 
            {
                block_encrypt(&(aes->st), aes->IV, temp);
                for (j=0; j<aes->segment_size/8; j++) {
                    buffer[i+j] = str[i+j] ^ temp[j];
                }
                if (aes->segment_size == BLOCK_SIZE * 8) {
                    /* s == b: segment size is identical to 
                       the algorithm block size */
                    memcpy(aes->IV, buffer + i, BLOCK_SIZE);
                }
                else if ((aes->segment_size % 8) == 0) {
                    int sz = aes->segment_size/8;
                    memmove(aes->IV, aes->IV + sz, 
                        BLOCK_SIZE-sz);
                    memcpy(aes->IV + BLOCK_SIZE - sz, buffer + i,
                           sz);
                }
                else {
                    /* segment_size is not a multiple of 8; 
                       currently this can't happen */
                }
            }
            break;

        case(MODE_OFB):
            for(i=0; i<len; i+=BLOCK_SIZE) 
            {
                block_encrypt(&(aes->st), aes->IV, temp);
                memcpy(aes->IV, temp, BLOCK_SIZE);
                for(j=0; j<BLOCK_SIZE; j++)
                {
                    buffer[i+j] = str[i+j] ^ temp[j];
                }
            }      
            break;
        default:
            free(buffer);
            luaL_error(pState, "not support mode");
            return 0;
    }

    lua_pushlstring(pState, buffer, len);
    free(buffer);
    return 1;
}

static int decrypt(lua_State* pState)
{
    AESObject* aes = (AESObject*)lua_touserdata(pState, 1);

    unsigned char *buffer, *str;
    unsigned char temp[BLOCK_SIZE];
    int i, j, len;

    str = lua_tolstring(pState, 2, &len);
    if (len == 0)
    {
        lua_pushstring(pState, "");
        return 1;
    }

    if ( (len % BLOCK_SIZE) !=0 && (aes->mode!=MODE_CFB))
    {
        luaL_error(pState, 
                 "Input strings must be "
                 "a multiple of %i in length",
                 BLOCK_SIZE);
        return 0;
    }
    if (aes->mode == MODE_CFB && 
        (len % (aes->segment_size/8) !=0)) {
        luaL_error(pState, 
                 "aInput strings must be a multiple of "
                 "the segment size %i in length",
                 aes->segment_size/8);
        return 0;
    }

    buffer = (char*)malloc(len);
    if (!buffer)
    {
        luaL_error(pState, "alloc memory error");
        return 0;
    }

    switch(aes->mode)
    {
        case(MODE_ECB):      
            for(i=0; i<len; i+=BLOCK_SIZE) 
            {
                block_decrypt(&(aes->st), str+i, buffer+i);
            }
            break;

        case(MODE_CBC):      
            for(i=0; i<len; i+=BLOCK_SIZE) 
            {
                memcpy(aes->oldCipher, aes->IV, BLOCK_SIZE);
                block_decrypt(&(aes->st), str+i, temp);
                for(j=0; j<BLOCK_SIZE; j++) 
                {
                    buffer[i+j]=temp[j]^aes->IV[j];
                    aes->IV[j]=str[i+j];
                }
            }
            break;

        case(MODE_CFB):      
            for(i=0; i<len; i+=aes->segment_size/8) 
            {
                block_encrypt(&(aes->st), aes->IV, temp);
                for (j=0; j<aes->segment_size/8; j++) {
                    buffer[i+j] = str[i+j]^temp[j];
                }
                if (aes->segment_size == BLOCK_SIZE * 8) {
                    /* s == b: segment size is identical to 
                       the algorithm block size */
                    memcpy(aes->IV, str + i, BLOCK_SIZE);
                }
                else if ((aes->segment_size % 8) == 0) {
                    int sz = aes->segment_size/8;
                    memmove(aes->IV, aes->IV + sz, 
                        BLOCK_SIZE-sz);
                    memcpy(aes->IV + BLOCK_SIZE - sz, str + i, 
                           sz);
                }
                else {
                    /* segment_size is not a multiple of 8; 
                       currently this can't happen */
                }
            }
            break;

        case (MODE_OFB):
            for(i=0; i<len; i+=BLOCK_SIZE) 
            {
                block_encrypt(&(aes->st), aes->IV, temp);
                memcpy(aes->IV, temp, BLOCK_SIZE);
                for(j=0; j<BLOCK_SIZE; j++)
                {
                    buffer[i+j] = str[i+j] ^ aes->IV[j];
                }
            }      
            break;

        default:
            free(buffer);
            luaL_error(pState, "not support mode");
            return 0;
    }
    lua_pushlstring(pState, buffer, len);
    free(buffer);
    return 1;
}

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

    lua_newtable(pState);
    lua_pushlightuserdata(pState, &pycrypto_aes_key);
    lua_pushvalue(pState, -2);
    lua_settable(pState, LUA_REGISTRYINDEX);

    lua_pushvalue(pState, -1);
    lua_setfield(pState, -2, "__index");
    luaL_register(pState, NULL, regMeta);

    luaL_register(pState, "pycrypto_aes", reg);

    lua_pushliteral(pState, VERSION);
    lua_setfield(pState, -2, "version");

    registerMode(pState, MODE_ECB, "MODE_ECB");
    registerMode(pState, MODE_CBC, "MODE_CBC");
    registerMode(pState, MODE_CFB, "MODE_CFB");
    registerMode(pState, MODE_OFB, "MODE_OFB");

    return 1;
}

/* vi:ai et sw=4 ts=4:
 */
