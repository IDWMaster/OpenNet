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
		msa->ImportParameters(rsaArguments);

		array<unsigned char>^ manData = gcnew array<unsigned char>(dlen);
		pin_ptr<unsigned char> mc = &manData[0];
		memcpy(mc, data, dlen);
		array<unsigned char>^ sigData = gcnew array<unsigned char>(slen);
		pin_ptr<unsigned char> sc = &sigData[0];
		memcpy(sc, signature, slen);
		bool retval = msa->VerifyData(manData, SHA256::Create(), sigData);
		return retval;
	}
	size_t CreateSignature(const unsigned char* data, size_t dlen, unsigned char* privateKey, unsigned char* signature) {
		RSACryptoServiceProvider^ msa = gcnew RSACryptoServiceProvider();
		RSAParameters rsaArguments;
		
		unsigned char* str = (unsigned char*)privateKey;
	
		uint32_t len;
		R(len);
		rsaArguments.Modulus = gcnew array<unsigned char>(len);
		pin_ptr<unsigned char> ma = &rsaArguments.Modulus[0];
		memcpy(ma, str, len);
		R(len);
		rsaArguments.Exponent = gcnew array<unsigned char>(len);
		pin_ptr<unsigned char> mb = &rsaArguments.Exponent[0];
		memcpy(mb, str, len);
		R(len);
		rsaArguments.D = gcnew array<unsigned char>(len);
		pin_ptr<unsigned char> mc = &rsaArguments.Exponent[0];
		memcpy(mc, str, len);
		msa->ImportParameters(rsaArguments);
		bool m = false;

		if (signature == 0) {
			signature = new unsigned char[msa->KeySize/8];
			m = true;
		}
		
		array<unsigned char>^ mandat = gcnew array<unsigned char>(dlen);
		pin_ptr<unsigned char> mptr = &mandat[0];
		memcpy(mptr, data, dlen);


		//The data was signed after this line!
		array<unsigned char>^ signedData = msa->SignData(mandat, SHA256::Create());
		pin_ptr<unsigned char> signedData_ptr = &signedData[0];
		if (signature) {
			memcpy(signature, signedData_ptr, signedData->Length);
		}
		if (!VerifySignature((unsigned char*)data, dlen, signature, signedData->Length, privateKey)) {
			
			abort();
		}



		if (m) {
			delete[] signature;
		}
		



		return signedData->Length;
	}
}