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
GGDNS_SetTimeoutInterval(2000);
//sleep(1);
if(argc == 1) {
	printf("HELP:\ndistauth enumPrivateKeys -- Enumerates private keys\ndistauth makeInternet privateKey -- Makes an Internet and digitally signs it with the specified private key\nsignRecord -- Digitally signs and imports a record piped from STDIN with the specified private key, and exports the signature to stdout.\nenumHosts -- Enumerates hosts for a given authoritative domain by referencing the nearest pointer. Returns a list of GUIDs\ngetDomainPtr -- Retrieves a domain pointer for a specified domain.\nrequestDomain -- requests a domain. The domain must be in the format domainName.parent, where domainName is the child domain being requested, and parent is the pointer to the authoritative object to which the request is being made. Also requires a signing certificate to be specified.\nupdateHost -- Associates host information with the specified domain (requires a pointer to the domain as an argument)\ngetHost -- Retrieves a host record for a specified domain pointer.\nresolveDomain -- Resolves a domain using a specified key.\n");

}else {
	if(argv[1] == std::string("enumPrivateKeys")) {
		bool(*enumCallback)(void*, const char*);
		void* thisptr = C([&](const char* name){
		    printf("%s\n",name);
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

			}else {
				if(argv[1] == std::string("enumHosts")) {
					if(argc != 3) {
						printf("Invalid number of arguments (expected 2)");
					}else {
						void* thisptr;
						void(*cb)(void*,unsigned char*,size_t);
						thisptr = C([&](unsigned char* data, size_t len){
							if(len % 16 == 0) {
								for(size_t i = 0;i<len;i+=16) {
									char mander[256]; //Convert a binary representation of the GUID to a Charmander.
									memset(mander,0,256);
									uuid_unparse(data,mander);
									printf("%s\n",mander);
								}
							}
						},cb);
						GGDNS_GetGuidListForObject(argv[2],thisptr,cb);
					}
				}else {
					if(argv[1] == std::string("getDomainPtr")) {
						std::string val = DotQuery(argv[2]);
						printf("%s\n",val.data());
					}else {
						if(argv[1] == std::string("requestDomain")) {
							const char* fullDomain = argv[2];
							const char* parentDot = argv[2];
							while(*parentDot != '.' && *parentDot != 0){parentDot++;};

								std::string parentObject = DotQuery(parentDot+1);
								std::string mf = std::string(fullDomain,parentDot);
								void* thisptr;
								void(*cb)(void*,unsigned char*,size_t);
								thisptr = C([&](unsigned char* data,size_t len){
									write(STDOUT_FILENO,data,len);
								},cb);
								GGDNS_MakeDomain(mf.data(),parentDot+1,argv[3],thisptr,cb);
						}else {
							if(argv[1] == std::string("updateHost")) {
								unsigned char data[1024*4];
								int avail = read(STDIN_FILENO,data,1024*4);
								GGDNS_MakeHost(argv[2],data,avail);
							}else {
								if(argv[1] == std::string("getHost")) {
									void* thisptr;
									void(*cb)(void*,unsigned char*,size_t);
									thisptr = C([&](unsigned char* data,size_t len){
										write(STDIN_FILENO,data,len);
									},cb);
									GGDNS_GetGuidListForObject(argv[2],thisptr,cb);
								}else {
									if(argv[1] == std::string("resolveDomain")) {
										sleep(2);
										unsigned char output[16];
										char mkr[256];
										memset(mkr,0,256);
										printf("Resolving domain\n");
										if(GGDNS_Resolve(argv[2],argv[3],output)) {
											uuid_unparse(output,mkr);
											printf("Found domain: %s\n",mkr);
										}else {
											printf("Epic fail.\n");
										}

									}
								}
							}
						}
					}
				}
			}
		}
	}
}

sleep(-1);
}
