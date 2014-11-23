//
//  CryptLib.m
//  CryptLib
//
//  Created by Brian Bosak on 11/22/14.
//  Copyright (c) 2014 Brian Bosak. All rights reserved.
//
#import "CryptLib.h"
#include "OpenAuth.h"
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#import <EasyApple.h>
@implementation CryptLib {
    void* db;
}
-(id)init {
    self = [super init];
    //Open database
    //TODO: Fix DB path (path needs to be Apple-fied. Can't just do an fopen on a file. No. That's too easy!
    //have to do a whole bunch of complex stuff first!)
    db = OpenNet_OAuthInitialize();
    
    return self;
}
-(void)dealloc {
    OpenNet_OAuthDestroy(db);
}
@end

static char filename[250];
const char* GetKeyDbFileName() {
   NSString* realpath = GetRealPath("key.db");
    memcpy(filename, realpath.UTF8String, realpath.length);
    return filename;
}
void* CreateHash() {
    SHA_CTX* ctx = (SHA_CTX*)malloc(sizeof(SHA_CTX));
    SHA1_Init(ctx);
    return ctx;
}
void UpdateHash(void* hash, const unsigned char* data, size_t sz) {
    SHA_CTX* ctx = hash;
    SHA1_Update(ctx, data, sz);
}
void FinalizeHash(void* hash, unsigned char* output) {
    SHA1_Final(output, hash);
}
bool VerifySignature(unsigned char* data, size_t dlen, unsigned char* signature, size_t slen, unsigned char* pubkey) {
    RSA* msa = RSA_new();
    //MOD, PUB_EXP, PRIV_EXP
    //msa->n; //mod
    //msa->d;
    if(msa->d) {
        abort();
    }
    uint32_t len;
    memcpy(&len, pubkey, 4);
    pubkey+=4;
    msa->d = BN_new();
    BN_bin2bn(pubkey, len, msa->d);
    memcpy(&len, pubkey, 4);
    pubkey+=4;
    msa->e = BN_new();
    BN_bin2bn(pubkey, len, msa->e);
    bool retval = RSA_verify(NID_sha1, data, (int)dlen, signature, (int)slen, msa);
    RSA_free(msa);
    return retval;
    }
size_t CreateSignature(const unsigned char* data, size_t dlen, unsigned char* privateKey, unsigned char* signature);
bool isValidKey(unsigned char* data, size_t length, bool* isPrivate) {
    *isPrivate = false;
    uint32_t len;
    if(length<4) {
        return false;
    }
    memcpy(&len, data, 4);
    length-=4;
    data+=4;
    if (length<len) {
        return false;
    }
    data+=len;
    length-=len;
    if(length<4) {
        return false;
    }
    memcpy(&len, data, 4);
    length-=len;
    data+=len;
    if (length>=4) {
        *isPrivate = true;
        memcpy(&len, data, 4);
        length-=4;
        data+=4;
        if (length<len) {
            return false;
        }
        return true;
    }else {
        return true;
    }
    
}
unsigned char* CreatePrivateKey(size_t* len, size_t* pubLen) {
    //MOD, PUB_EXP, PRIV_EXP
    RSA* msa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, 65537);
    RSA_generate_key_ex(msa, 4096, e, 0);
    BN_free(e);
    size_t pubSize = 4+BN_num_bytes(msa->n)+4+BN_num_bytes(msa->e);
    size_t privSize = 4+BN_num_bytes(msa->d);
    unsigned char* retval = malloc(pubSize+privSize);
    unsigned char* izard = retval;
    uint32_t count = BN_num_bytes(msa->n);
    memcpy(izard, &count, 4);
    izard+=4;
    BN_bn2bin(msa->n, izard);
    izard+=count;
    count = BN_num_bytes(msa->e);
    memcpy(izard, &count, 4);
    izard+=4;
    BN_bn2bin(msa->e, izard);
    izard+=count;
    count = BN_num_bytes(msa->d);
    memcpy(izard, &count, 4);
    izard+=4;
    BN_bn2bin(msa->d, izard);
    *len = pubSize+privSize;
    *pubLen = pubSize;
    RSA_free(msa);
    return retval;
}