#include "OpenAuth.h"
#include "sqlite3.h"
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
std::string string_to_hex(const unsigned char* input, size_t len)
{
	static const char* const lut = "0123456789ABCDEF";

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

std::string hex_to_string(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();
	if (len & 1) throw std::invalid_argument("odd length");

	std::string output;
	output.reserve(len / 2);
	for (size_t i = 0; i < len; i += 2)
	{
		char a = input[i];
		const char* p = std::lower_bound(lut, lut + 16, a);
		if (*p != a) throw std::invalid_argument("not a hex digit");

		char b = input[i + 1];
		const char* q = std::lower_bound(lut, lut + 16, b);
		if (*q != b) throw std::invalid_argument("not a hex digit");

		output.push_back(((p - lut) << 4) | (q - lut));
	}
	return output;
}




class IDisposable {
public:
	virtual ~IDisposable(){};
};
class SafeResizableBuffer {
public:
	//This is a car
	unsigned char* buffer;
	size_t sz;
	SafeResizableBuffer() {
		buffer = 0;
		position = 0;
	}
	template<typename T>
	void Write(const T& value) {
		Write(&value,sizeof(value));
	}
	template<typename T>
	int Read(T& value) {
		return Read(&value,sizeof(value));
	}
	size_t position;
	int Read(void* buffer, int count) {
		if (position + count > sz) {
			//BARFIZARD!
			throw "up";
		}
		memcpy(buffer, this->buffer + position, count);
		position += count;
		return count;
	}
	void Write(const void* buffer, int count) {
		if (position + count > sz) {
			size_t allocsz = std::max(position + count, sz * 2);
			unsigned char* izard = new unsigned char[allocsz];
			memcpy(izard,this->buffer,sz);
			delete[] this->buffer;
		}
		memcpy(this->buffer, buffer, count);
	}
	~SafeResizableBuffer() {
		if(buffer) {
		delete[] buffer;
		}
	}
};

class Certificate:public IDisposable {
public:
	std::vector<unsigned char> PublicKey;
	std::vector<unsigned char> PrivateKey;
    std::vector<unsigned char> Signature;
    std::string Authority;

};
class KeyDatabase:public IDisposable {
public:
	sqlite3* db;
	sqlite3_stmt* command_addcert;
	sqlite3_stmt* command_addobject;
	sqlite3_stmt* command_addkey;
	sqlite3_stmt* command_findcert;
    sqlite3_stmt* command_getPrivateKeys;
    sqlite3_stmt* command_findObject;
    sqlite3_stmt* command_findPrivateKey;
    sqlite3_stmt* command_enumerateCertificates;
    void EnumerateCertificates(void* thisptr,bool(*callback)(void*,const char*)) {
        int status;
        while ((status = sqlite3_step(command_enumerateCertificates)) != SQLITE_DONE) {
            if(status == SQLITE_ROW) {
            if(!callback(thisptr,(const char*)sqlite3_column_text(command_enumerateCertificates, 0))) {
                break;
            }
            }
        }
        sqlite3_reset(command_enumerateCertificates);
        
    }
    std::string AddCertificate(Certificate* cert) {
		void* hash = CreateHash();
		UpdateHash(hash, cert->PublicKey.data(), cert->PublicKey.size());
		//Use Unsigned Charizard's thumbprint
		unsigned char izard[20];
		FinalizeHash(hash, izard);

		
		std::string thumbprint = string_to_hex(izard,20);

		sqlite3_bind_text(command_addcert, 1, thumbprint.data(), thumbprint.size(), 0);
		sqlite3_bind_blob(command_addcert, 2, cert->PublicKey.data(), cert->PublicKey.size(),0);
		sqlite3_bind_text(command_addcert, 3, cert->Authority.data(), cert->Authority.size(), 0);
        sqlite3_bind_blob(command_addcert, 4, cert->Signature.data(),cert->Signature.size(),0);

		//Insert ificate
		int val;
        while ((val = sqlite3_step(command_addcert)) != SQLITE_DONE){  };
		
		sqlite3_reset(command_addcert);
		if (val == SQLITE_DONE) {
            if(cert->PrivateKey.size()) {
                //Add private key to database

                unsigned char* data = cert->PrivateKey.data();
                sqlite3_bind_text(command_addkey,1,thumbprint.data(),thumbprint.size(),0);
                sqlite3_bind_blob(command_addkey,2,data,cert->PrivateKey.size(),0);
                val = 0;
                while((val = sqlite3_step(command_addkey)) != SQLITE_DONE){};
                sqlite3_reset(command_addkey);
                return thumbprint;

            }
            return thumbprint;
		}
		return "";
	}
	Certificate* FindCertificate(const std::string& thumbprint) {
		sqlite3_bind_text(command_findcert, 1, thumbprint.data(), thumbprint.size(), 0);
		int val;
		Certificate* retval = 0;
		while ((val = sqlite3_step(command_findcert)) != SQLITE_DONE) {
			if (val == SQLITE_ROW) {
				retval = new Certificate();
				retval->PublicKey.resize(sqlite3_column_bytes(command_findcert, 1));
				memcpy(retval->PublicKey.data(), sqlite3_column_blob(command_findcert, 1),retval->PublicKey.size());
				retval->Authority = (const char*)sqlite3_column_text(command_findcert, 2);
                retval->Signature.resize(sqlite3_column_bytes(command_findcert,3));
                memcpy(retval->Signature.data(),sqlite3_column_blob(command_findcert,3),sqlite3_column_bytes(command_findcert,3));
                break;
			}
		}
        sqlite3_reset(command_findcert);
        if(retval) {
            //Locate private key
            while((val = sqlite3_step(command_findPrivateKey)) != SQLITE_DONE) {
                if(val == SQLITE_ROW) {
                const void* data = sqlite3_column_blob(command_findPrivateKey,1);
                size_t sz = sqlite3_column_bytes(command_findPrivateKey,1);
                retval->PrivateKey.resize(sz);
                memcpy(retval->PrivateKey.data(),data,sz);
                break;
                }
            }
            sqlite3_reset(command_findPrivateKey);
        }
        return retval;
	}
    void EnumeratePrivateKeys(bool(*callback)(const char* thumbprint)) {
        int val;
        while((val = sqlite3_step(command_getPrivateKeys)) != SQLITE_DONE) {
            if(val == SQLITE_ROW) {
                if(!callback((const char*)sqlite3_column_text(command_getPrivateKeys,0))) {
                    break;
                }
            }
        }
        sqlite3_reset(command_getPrivateKeys);
    }

	KeyDatabase() {
		sqlite3_open(GetKeyDbFileName(), &db);
		char* err;
		//The thumbprint is a hash of the public key
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS Certificates (Thumbprint TEXT, PublicKey BLOB, Authority TEXT, Signature BLOB, PRIMARY KEY(Thumbprint))",0,0,&err);
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS NamedObjects (Name TEXT, Authority TEXT, Signature BLOB, SignedData BLOB)", 0, 0, &err);
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS PrivateKeys (Thumbprint TEXT PRIMARY KEY, PrivateKey BLOB)",0,0,&err);
        std::string sql = "INSERT INTO Certificates VALUES (?, ?, ?, ?)";
		const char* parsed;
		sqlite3_prepare(db, sql.data(), (int)sql.size(), &command_addcert, &parsed);
        sql = "INSERT INTO NamedObjects VALUES (?, ?, ?, ?)";
		sqlite3_prepare(db, sql.data(), (int)sql.size(), &command_addobject, &parsed);
		sql = "INSERT INTO PrivateKeys VALUES (?, ?)";
		sqlite3_prepare(db, sql.data(), (int)sql.size(), &command_addkey, &parsed);
        sql = "SELECT * FROM Certificates WHERE Thumbprint = ?";
        sqlite3_prepare(db, sql.data(), (int)sql.size(), &command_findcert, &parsed);
        sql = "SELECT * FROM NamedObjects WHERE Name = ?";
        sqlite3_prepare(db, sql.data(), (int)sql.size(), &command_findObject, &parsed);
        sql = "SELECT * FROM PrivateKeys WHERE Thumbprint = ?";
        sqlite3_prepare(db, sql.data(), (int)sql.size(), &command_findPrivateKey, &parsed);
        sql = "SELECT * FROM PrivateKeys";
        sqlite3_prepare(db,sql.data(),(int)sql.size(),&command_getPrivateKeys,&parsed);
        sql = "SELECT * FROM Certificates";
        sqlite3_prepare(db,sql.data(),(int)sql.size(),&command_enumerateCertificates,&parsed);
        int status = 0;
        bool hasKey = false;
        while((status = sqlite3_step(command_getPrivateKeys)) != SQLITE_DONE) {
            if(status == SQLITE_ROW) {
            hasKey = true;
            }

        }
        if(!hasKey) {
            //Create a new key
            Certificate cert;
            size_t keylen;
            size_t publen;
            unsigned char* key = CreatePrivateKey(&keylen,&publen);
            cert.PrivateKey.resize(keylen);
            memcpy(cert.PrivateKey.data(),key,keylen);
            cert.PublicKey.resize(publen);
            memcpy(cert.PublicKey.data(),key,publen);
            if(AddCertificate(&cert).size() == 0) {
                throw "sideways";
            }
        }

	}
    bool AddObject(const NamedObject& obj, const char* name) {
        //Adds a named object to the database
        //Verify signature on BOTH name and data
        bool foundAuthority = false;
        Certificate* cert = FindCertificate(obj.authority);
        if(!cert) {
            return false;
        }
        size_t slen = strlen(name);
        unsigned char* mander = new unsigned char[slen+obj.bloblen];
        memcpy(mander,name,slen);
        memcpy(mander+slen,obj.blob,obj.bloblen);
        bool retval = VerifySignature(mander,slen+obj.bloblen,obj.signature,obj.siglen,cert->PublicKey.data());
        delete[] mander;
        if(retval) {
            //Name TEXT, Authority TEXT, Signature BLOB, SignedData BLOB
            sqlite3_bind_text(command_addobject,1,name,slen,0);
            sqlite3_bind_text(command_addobject,2,obj.authority,strlen(obj.authority),0);
            sqlite3_bind_blob(command_addobject,3,obj.signature,obj.siglen,0);
            sqlite3_bind_blob(command_addobject,4,obj.blob,obj.bloblen,0);
            while(sqlite3_step(command_addobject) != SQLITE_DONE) {}
            sqlite3_reset(command_addobject);
        }else {

        }
        return retval;
    }
    void RetrieveObject(const char* name, void* thisptr, void(*callback)(void*, NamedObject* val)) {

        NamedObject output;
        sqlite3_bind_text(command_findObject,1,name,strlen(name),0);
        int val;
        while((val = sqlite3_step(command_findObject)) != SQLITE_DONE) {
            if(val == SQLITE_ROW) {
                output.authority = (char*)sqlite3_column_text(command_findObject,1);
                output.signature = (unsigned char*)sqlite3_column_blob(command_findObject,2);
                output.siglen = sqlite3_column_bytes(command_findObject,2);
                output.blob = (unsigned char*)sqlite3_column_blob(command_findObject,3);
                output.bloblen = sqlite3_column_bytes(command_findObject,3);
                callback(thisptr,&output);
                break;
            }
        }
        sqlite3_reset(command_findObject);
    }
	~KeyDatabase() {
		sqlite3_finalize(command_addcert);
        sqlite3_finalize(command_addkey);
        sqlite3_finalize(command_addobject);
        sqlite3_finalize(command_findcert);
        sqlite3_finalize(command_findObject);
        sqlite3_finalize(command_findPrivateKey);
        sqlite3_finalize(command_getPrivateKeys);
        sqlite3_finalize(command_enumerateCertificates);
		sqlite3_close(db);
	}
};

extern "C" {
    void OpenNet_OAuthEnumPrivateKeys(void* db, void* thisptr, bool(*callback)(void* thisptr,const char* thumbprint)) {
        KeyDatabase* realdb = (KeyDatabase*)db;
        int status;
        while((status = sqlite3_step(realdb->command_getPrivateKeys)) != SQLITE_DONE) {
            if(status == SQLITE_ROW) {
                if(!callback(thisptr,(char*)sqlite3_column_text(realdb->command_getPrivateKeys,0))) {
                    break;
                }
            }
        }
        sqlite3_reset(realdb->command_getPrivateKeys);

    }
    void* OpenNet_OAuthInitialize() {
		return new KeyDatabase();
    }
    void OpenNet_OAuthDestroy(void* db) {
        delete (KeyDatabase*)db;
    }
    //Finds the trust anchor for a given certificate; as well as an indication of the resolution status
    void OpenNet_ResolveChain(void* db, const char* thumbprint, void* thisptr, void(*callback)(void*, const char*, bool)) {
    	KeyDatabase* keydb = (KeyDatabase*)db;
    	std::string current = thumbprint;
    	while(true) {

        	Certificate* cert = keydb->FindCertificate(current);
        	if(cert) {
        		if(cert->Authority.size() == 0) {
        			//We've reached the end of the chain.
        			callback(thisptr,current.data(),true);
        			delete cert;
        			break;
        		}else {
        			//Move on to the next one in the chain
        			Certificate* prev = cert;
        			current = prev->Authority;
        			delete prev;
        		}
        	}else {
        		//We've lost the chain (need to resolve missing link).
        		callback(thisptr,current.data(),false);
        		break;
        	}
    	}
    }
    void OpenNet_MakeObject(void* db, const char* name,  NamedObject* obj) {
        KeyDatabase* realdb = (KeyDatabase*)db;
        int status;
        sqlite3_bind_text(realdb->command_findPrivateKey,1,obj->authority,strlen(obj->authority),0);
        while((status = sqlite3_step(realdb->command_findPrivateKey)) != SQLITE_DONE) {
            if(status == SQLITE_ROW) {
                //Found key!
                unsigned char* privKey = (unsigned char*)sqlite3_column_blob(realdb->command_findPrivateKey,1);
                size_t privLen = sqlite3_column_bytes(realdb->command_findPrivateKey,1);
                //Sign blob using private key
                size_t signedBlobLen = strlen(name)+obj->bloblen;
                unsigned char* signedBlob = (unsigned char*)malloc(signedBlobLen);
                memcpy(signedBlob,name,strlen(name));
                memcpy(signedBlob+strlen(name),obj->blob,obj->bloblen);
                size_t siglen = CreateSignature(signedBlob,signedBlobLen,privKey,0);
                 //Insert into database
                obj->signature = (unsigned char*)malloc(siglen);
                obj->siglen = CreateSignature(signedBlob,signedBlobLen,privKey,obj->signature);
                OpenNet_AddObject(db,name,obj);
                free(signedBlob);
                free(obj->signature);
                break;
            }
        }
        sqlite3_reset(realdb->command_findPrivateKey);
    }

    bool OpenNet_AddObject(void* db, const char* name, const NamedObject* obj) {
        KeyDatabase* keydb = (KeyDatabase*)db;
        return keydb->AddObject(*obj,name);
        
    }
    void OpenNet_RetrieveCertificate(void* db, const char* thumbprint,  void* thisptr,  void(*callback)(void*,OCertificate*)) {
    	KeyDatabase* keydb = (KeyDatabase*)db;
    	Certificate* cert = keydb->FindCertificate(thumbprint);
    	if(cert) {
    		OCertificate abi;
    		abi.authority = (char*)cert->Authority.data();
    		abi.pubLen = cert->PublicKey.size();
    		abi.pubkey = (unsigned char*)cert->PublicKey.data();
    		abi.siglen = cert->Signature.size();
    		abi.signature = (unsigned char*)cert->Signature.data();
    		callback(thisptr,&abi);
    		delete cert;
    	}else {
    		callback(thisptr,0);
    	}
    }
    void OpenNet_AddCertificate(void* db,const OCertificate* abi, void* thisptr, void(*callback)(void*,const char*)) {
    	Certificate cert;
    	cert.Authority = abi->authority;
    	cert.PublicKey.resize(abi->pubLen);
    	cert.Signature.resize(abi->siglen);
    	memcpy(cert.PublicKey.data(),abi->pubkey,abi->pubLen);
    	memcpy(cert.Signature.data(),abi->signature,abi->siglen);
    	KeyDatabase* keydb = (KeyDatabase*)db;
    	bool priv;
    	if(isValidKey(abi->pubkey,abi->pubLen,&priv)) {
    		if(priv) {
    			if(callback) {
    				callback(thisptr,0);
    			}
    			return;
    		}
    		std::string retval = keydb->AddCertificate(&cert);
    		if(callback) {
    			callback(thisptr,retval.data());
    		}
    	}else {
    		if(callback) {
    			callback(thisptr,0);
    		}
    	}
    }

    void OpenNet_Retrieve(void* db, const char* name, void* thisptr, void(*callback)(void *, NamedObject *)) {
        KeyDatabase* keydb = (KeyDatabase*)db;
        keydb->RetrieveObject(name,thisptr,callback);
    }
}
