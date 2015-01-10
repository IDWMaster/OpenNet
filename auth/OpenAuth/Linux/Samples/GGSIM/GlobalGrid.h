#include <stdint.h>
#include <map>
#include <mutex>
#include <unistd.h>
#include <condition_variable>
typedef struct {
    int64_t value[2];
} GlobalGrid_Identifier;
typedef struct {
    void* thisptr;
    void(*onDestroyed)(void* thisptr);
    void(*onReceived)(void* thisptr, unsigned char* src, int32_t srcPort, unsigned char* data, size_t sz);
} ReceiveCallback;
extern "C" {
void GlobalGrid_Send(void* connectionManager, unsigned char* dest,int32_t srcportno,int32_t destportno,unsigned char* data, size_t sz);
size_t GlobalGrid_GetPeerList(void* connectionManager,GlobalGrid_Identifier** list);
void GlobalGrid_FreePeerList(GlobalGrid_Identifier* list);
void GlobalGrid_OpenPort(void* connectionManager,int32_t portno,ReceiveCallback onReceived);
void GlobalGrid_GetID(void* connectionManager, unsigned char* id);
}
namespace GlobalGrid {
class P2PConnectionManager {
public:
	void* nativePtr;
	void RegisterProtocol(void* proto) {}	
};
}
