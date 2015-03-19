// This is the main DLL file.

#include "stdafx.h"

#include "OpenAuth.h"
using namespace System;
using namespace System::IO;
using namespace System::Security;
using namespace System::Security::Cryptography;
using namespace System::Runtime::InteropServices;

class IDisposable {
public:
	virtual ~IDisposable(){};
};
template<typename T>
class ManagedObject:public ::IDisposable {
public:
	GCHandle handle;
	ManagedObject(T^ obj){
		handle = GCHandle::Alloc(obj);
	}
	operator T ^ () {
		return (T^)handle.Target;
	}
	~ManagedObject() {
		handle.Free();
	}
};


#define R(output) Read(str,output)
template<typename T>
static void Read(unsigned char*& str, T& output) {
	memcpy(&output, str, sizeof(output));
	str += sizeof(output);
}



#define CP(val,type)((type*)val)
#define C(val,type)((type)val)
extern "C" {
	void* CreateHash() {
		return new ManagedObject<MemoryStream>(gcnew MemoryStream());
	}
	void UpdateHash(void* hash, const unsigned char* data, size_t sz) {
		MemoryStream^ str = *CP(hash, ManagedObject<MemoryStream>);
		array<unsigned char>^ mray = gcnew array<unsigned char>(sz);
		str->Write(mray, 0, sz);
	}
	void FinalizeHash(void* hash, unsigned char* output) {
		MemoryStream^ myStream = *CP(hash, ManagedObject<MemoryStream>);
		array<unsigned char>^ dataBytes = myStream->ToArray();
		SHA256^ mhash = SHA256::Create();
		mhash->ComputeHash(dataBytes);
		pin_ptr<unsigned char> rawData = &dataBytes[0];
		memcpy(output, rawData, dataBytes->Length);
	}
	
	bool VerifySignature(unsigned char* data, size_t dlen, unsigned char* signature, size_t slen, unsigned char* key) {
		RSACryptoServiceProvider^ msa = gcnew RSACryptoServiceProvider();
		RSAParameters rsaArguments;
		unsigned char hash[SHA256_DIGEST_LENGTH];
		SHA256(data, (int)dlen, hash);
		unsigned char* str = (unsigned char*)key;
		uint32_t len;
		R(len);
		rsaArguments.Modulus = gcnew array<unsigned char>(len);
		pin_ptr<unsigned char> ma = &rsaArguments.Modulus[0];
		memcpy(ma, str, len);
		R(len);
		rsaArguments.Exponent = gcnew array<unsigned char>(len);
		pin_ptr<unsigned char> mb = &rsaArguments.Exponent[0];
		memcpy(mb, str, len);

		bool retval = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, slen, msa);

		RSA_free(msa);
		return retval;
	}
	size_t OpenNet_CreateSignature(const unsigned char* data, size_t dlen, unsigned char* signature) {
		RSASSA_PKCS1v15_SHA_Signer signer;
		size_t mlen = signer.MaxSignatureLength();
		bool rst = false;
		if (signature == 0) {
			signature = new unsigned char[mlen];
			rst = true;
		}
		size_t retval = signer.SignMessage(CryptoPP::RandomNumberGenerator(), data, dlen, signature);
		if (rst) {
			delete[] signature;
		}
		return retval;
	}
}