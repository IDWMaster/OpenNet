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
int main(int argc, char** argv) {

    GlobalGrid::P2PConnectionManager mngr;
GlobalGrid::InternetProtocol ip(5809,&mngr);
mngr.RegisterProtocol(&ip);
GGDNS_Init(mngr.nativePtr);
//Script it. Automated tests for GlobalGrid GGDNS integration
std::string thumbprint;
bool(*enumCallback)(void*, const char*);
void* thisptr = C([&](const char* name){
    thumbprint = name;
    return false;
},enumCallback);
OpenNet_OAuthEnumCertficates(keydb,thisptr,enumCallback);
NamedObject object;
object.authority = (char*)thumbprint.data();
const char* izard = "PIKACHU!!!!!!!!!!";
object.blob = (unsigned char*)izard;
object.bloblen = strlen(izard)+1;
OpenNet_AddObject(keydb,"Charmander",&object);


}
