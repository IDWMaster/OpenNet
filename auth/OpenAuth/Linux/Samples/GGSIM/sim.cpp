//These really aren't meant to do anything. Just a stub for testing local features of
//GlobalGrid programs without a GlobalGrid license.
//In other words; it just is a fakes library so that the program can compile
//and run without networking features. This library may later be expanded to actually do some networking stuff; but it would use
//IP (Internet Protocol) rather than GlobalGrid.
//For an actual GlobalGrid license; please contact IDWMaster on GitHub.
#include "GlobalGrid.h"
extern "C" {
void GlobalGrid_Send(void* connectionManager, unsigned char* dest,int32_t srcportno,int32_t destportno,unsigned char* data, size_t sz) {

}

size_t GlobalGrid_GetPeerList(void* connectionManager,GlobalGrid_Identifier** list) {
    return 0;
}

void GlobalGrid_FreePeerList(GlobalGrid_Identifier* list) {

}

void GlobalGrid_OpenPort(void* connectionManager,int32_t portno,ReceiveCallback onReceived) {

}

void GlobalGrid_GetID(void* connectionManager, unsigned char* id) {

}

}
