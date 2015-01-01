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
NamedObject object;
object.authority = (char*)thumbprint.data();
const char* izard = "PIKACHU!!!!!!!!!!";
object.blob = (unsigned char*)izard;
object.bloblen = strlen(izard)+1;
printf("Private key thumbprint = %s; signing object....\n",thumbprint.data());
GGDNS_MakeObject("Charmander",&object);
if(object.signature) {
    printf("Signed object and stored in local database.\n");
}
void(*callback)(void*,NamedObject*);
thisptr = C([=](NamedObject* obj){
    if(obj) {
        printf("%s\n",obj->blob);
    }else {
        printf("Error: Object not found\n");
    }
},callback);
GGDNS_RunQuery("Charmander",thisptr,callback);
}
