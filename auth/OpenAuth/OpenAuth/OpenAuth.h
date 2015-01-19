// OpenAuth.h

#ifndef OpenNet_Auth
#define OpenNet_Auth

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    //The authority who signed the blob
    char* authority;
    //The blob
    unsigned char* blob;
    //The length of the blob
    size_t bloblen;
    unsigned char* signature;
    size_t siglen;
} NamedObject;
typedef struct {
	char* authority;
	unsigned char* pubkey;
	size_t pubLen;
	unsigned char* signature;
	size_t siglen;
} OCertificate;
#ifdef __cplusplus
template<typename F, typename... args, typename R>
static R unsafe_c_callback(void* thisptr,args... a) {
    return (*((F*)thisptr))(a...);
}



template<typename F, typename... args, typename R>
static void* C(const F& callback, R(*&fptr)(void*,args...)) {
    fptr = unsafe_c_callback<F,args...>;
    return (void*)&callback;
}
extern "C" {
#endif
    void* OpenNet_OAuthInitialize();
    void OpenNet_Retrieve(void* db, const char* name, void* thisptr, void(*callback)(void* thisptr,NamedObject* obj));
    bool OpenNet_AddObject(void* db, const char* name, const NamedObject* obj);
    void OpenNet_OAuthDestroy(void* db);
    void OpenNet_OAuthEnumPrivateKeys(void* db, void* thisptr, bool(*callback)(void* thisptr,const char* thumbprint));
    void OpenNet_MakeObject(void* db, const char* name,  NamedObject* obj, bool update);
    void OpenNet_AddCertificate(void* db,const OCertificate* abi, void* thisptr, void(*callback)(void*,const char*));
    void OpenNet_RetrieveCertificate(void* db, const char* thumbprint,  void* thisptr,  void(*callback)(void*,OCertificate*));
    //Finds the trust anchor for a given certificate; as well as an indication of the resolution status
    void OpenNet_ResolveChain(void* db, const char* thumbprint, void* thisptr, void(*callback)(void*, const char*, bool));
    bool OpenNet_UpdateObject(void* db, const char* name, const NamedObject* obj);
    void OpenNet_AddDomain(void* db, const char* name, const char* parent, const char* objid);
    void OpenNet_FindReverseDomain(void* db, const char* objid, void* thisptr, void(*callback)(void*,const char*, const char*));
    void OpenNet_FindDomain(void* db, const char* domain, const char* parent, void* thisptr, void(*callback)(void*, const char*));
    void DMCA_TakedownBlob(void* db,const char* name);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
//OS-Specific routines
extern "C" {
	//Creates a 20-byte hash
	void* CreateHash();
	void UpdateHash(void* hash, const unsigned char* data, size_t sz);
	void FinalizeHash(void* hash, unsigned char* output);
    bool VerifySignature(unsigned char* data, size_t dlen, unsigned char* signature, size_t slen, unsigned char* key);
    size_t CreateSignature(const unsigned char* data, size_t dlen, unsigned char* privateKey, unsigned char* signature);
    bool isValidKey(unsigned char* data, size_t len, bool* isPrivate);
    unsigned char* CreatePrivateKey(size_t* len, size_t* pubLen);
    const char* GetKeyDbFileName();
}

class SafeBuffer {
public:
    void* ptr;
    size_t sz;
    int Read(unsigned char* buffer, int count) {
        if (pos + count > sz) {
            throw "up";
        }

        memcpy(buffer, ((unsigned char*)ptr) + pos, count);

        pos += count;
        return count;
    }
    void Write(unsigned char* data, int count) {
        if (pos + count > sz) {
            throw "up";
        }
        memcpy(((unsigned char*)ptr) + pos, data, count);

        pos += count;
    }
    size_t pos;
    int64_t GetLength() {
        return (int64_t)sz;
    }
    template<typename T>
    void Read(T& val) {
        Read((unsigned char*)&val, sizeof(val));
    }
    template<typename T>
    void Write(const T& val) {
        Write((unsigned char*)&val, sizeof(val));
    }
    SafeBuffer(void* ptr, size_t sz) {
        this->ptr = ptr;
        this->sz = sz;
        pos = 0;
    }
};

#endif
#endif
