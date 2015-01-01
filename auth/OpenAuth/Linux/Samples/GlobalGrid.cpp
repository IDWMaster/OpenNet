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


#include <functional>

int main(int argc, char** argv) {

    GlobalGrid::P2PConnectionManager mngr;
GlobalGrid::InternetProtocol ip(5809,&mngr);
mngr.RegisterProtocol(&ip);
GGDNS_Init(mngr.nativePtr);
//Script it. Automated tests for GlobalGrid GGDNS integration
printf("Scanning for private key....\n");
std::string thumbprint;
bool(*enumCallback)(void*, const char*);
void* thisptr = C([&](const char* name){
    thumbprint = name;
    return false;
},enumCallback);
GGDNS_EnumPrivateKeys(thisptr,enumCallback);
printf("Ready for commands");
char buffer[256];
auto readline = [&](){
	read(STDIN_FILENO,buffer,256);
	return std::string(buffer);
};
std::function<void()> menu = [&]() {
	printf("\n\n0. Run GGDNS query\n1. Add GGDNS object\nPlease enter a selection: ");
	std::string input = readline();
	switch(input[0]) {
	case '0':
	{

		printf("Enter object ID: \n");
		std::mutex m;
		std::condition_variable evt;
		std::unique_lock<std::mutex> l(m);
		void(*callback)(void*,NamedObject*);
		void* thisptr = C([&](NamedObject* obj){
			if(obj) {
				printf("%s\n",(char*)obj->blob);
			}else {
				printf("Object not found (NOTE: GGDNS entries are case-sensitive)\n");
			}
			evt.notify_all();
		},callback);
		std::string id = readline();
		GGDNS_RunQuery(id.data(),thisptr,callback);
		evt.wait(l);
		printf("Operation complete\n");
		menu();
	}
		break;
	case '1':
	{
		printf("Enter GGDNS identifier\n");
		std::string id = readline();
		printf("Enter GGDNS value (up to 4KB)\n ");
		std::string val = readline();
		NamedObject obj;
		obj.authority = (char*)thumbprint.data();
		obj.blob = (unsigned char*)val.data();
		obj.bloblen = val.size();
		GGDNS_MakeObject(id.data(),&obj,0,0);
		printf("Object created successfully.\n");
		menu();
	}
		break;
	}
};
menu();
sleep(-1);
}
