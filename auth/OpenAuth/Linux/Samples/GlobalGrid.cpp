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

while(true) {
    printf("Test options:\n");
    printf("0. Add object\n");
    char mander[256];
    memset(mander,0,256);
    read(1,mander,256);
    switch(mander[0]) {
    case '0':
    {
        printf("Enter object name: ");
        memset(mander,0,256);
        read(1,mander,256);
        std::string objname = mander;
        printf("Enter object value (as string):");
        memset(mander,0,256);
        read(1,mander,256);
        std::string objval = mander;


    }
        break;
    }
}
}
