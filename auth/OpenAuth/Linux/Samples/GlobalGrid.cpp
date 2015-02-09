/* ***********************************************************
 * Build instructions
 * This file requires a proprietary library to build; as such
 * it is not included in the "make all" script.
 * To build this; you need a license to the proprietary
 * GlobalGrid networking protocol.
 * A license can be obtained from IDWNet Cloud Computing
 * by e-mailing the creator of this GIT repository.
 * GlobalGrid is currently compatible with Linux, Windows,
 * embedded and iOS systems.
 *************************************************************/

#include <iostream>
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <GGDNS.h>
#include <string>
#include <OpenAuth.h>
#include <uuid/uuid.h>

#include <functional>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include "LightThread.h"








int main(int argc, char** argv) {

std::shared_ptr<GlobalGrid::P2PConnectionManager> mngr = std::make_shared<GlobalGrid::P2PConnectionManager>();
GlobalGrid::InternetProtocol ip(5809,mngr);
mngr->RegisterProtocol(&ip);
GGDNS_Init(mngr->nativePtr);


if(argc == 1) {
	printf("HELP:\ndistauth enumPrivateKeys -- Enumerates private keys\ndistauth makeInternet privateKey -- Makes an Internet and digitally signs it with the specified private key\nsignRecord -- Digitally signs and imports a record piped from STDIN with the specified private key, and exports the signature to stdout.\n");

}else {
	if(argv[1] == std::string("enumPrivateKeys")) {
		bool(*enumCallback)(void*, const char*);
		void* thisptr = C([&](const char* name){
		    printf("%s\n");
		    return true;
		},enumCallback);
		GGDNS_EnumPrivateKeys(thisptr,enumCallback);
	}else {
		//We like making the Internetz
		//We also REALLY liek Mudkipz
		if(argv[1] == std::string("makeInternet")) {
			if(argc == 3) {
				unsigned char id[16];
				uuid_generate(id);
				char out[256];
				uuid_unparse(id,out);
				void(*cb)(void*,unsigned char*,size_t);
				void* thisptr = C([&](unsigned char* signedObject, size_t sz){
					write(STDOUT_FILENO,signedObject,sz);

				},cb);
				GGDNS_MakeDomain(out,"",argv[2],thisptr,cb);
				//printf("%s\n",out);
			}else {
				printf("Invalid number of arguments. Expected 2 (makeInternet and private key)\n");
			}
		}else {
			if(argv[1] == std::string("signRecord")) {
				unsigned char request[4096];
				int bytes = read(STDIN_FILENO,request,4096);
				NamedObject obj;
				obj.blob = request;
				obj.bloblen = bytes;
				obj.authority = argv[2];
				void* thisptr;
				void(*cb)(void*,bool);
				unsigned char name[16];
				uuid_generate(name);
				char nstr[256];
				memset(nstr,0,256);
				uuid_unparse(name,nstr);

				thisptr = C([&](bool success){
					if(success) {
					}else {
					}
				},cb);
				GGDNS_MakeObject(nstr,&obj,thisptr,cb);

				write(STDOUT_FILENO,nstr,strlen(nstr)+1);
				write(STDOUT_FILENO,obj.signature,obj.siglen);

			}
		}
	}
}
}
