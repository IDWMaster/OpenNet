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
#include "globalgrid/GlobalGrid.h"
#include "globalgrid/InternetProtocol.h"
#include "../OpenAuth.h"
#include <mutex>

template<typename F, typename... args, typename R>
static R unsafe_c_callback(void* thisptr,args... a) {
    return (*((F*)thisptr))(a...);
}



template<typename F, typename... args, typename R>
static void* C(const F& callback, R(*&fptr)(void*,args...)) {
    fptr = unsafe_c_callback<F,args...>;
    return (void*)&callback;
}


class BStream {
public:
    unsigned char* ptr;
    size_t length;
    BStream(unsigned char* buffer, size_t sz) {
        this->ptr = buffer;
        this->length = sz;
    }
    void Read(unsigned char* buffer, size_t len) {
        if(len>length) {
            throw "up";
        }
        memcpy(buffer,ptr,len);
        ptr+=len;
        length-=len;
    }
    template<typename T>
    T& Read(T& val) {
        Read((unsigned char*)&val,sizeof(T));
        return val;
    }
    char* ReadString() {
        char* retval = (char*)ptr;
        char mander;
        while(Read(mander) != 0){}
        return retval;
    }
};

static void* db;
static void processRequest(void* thisptr, unsigned char* src, int32_t srcPort, unsigned char* data, size_t sz) {
    //Received a DNS request; process it
    BStream s(data,sz);
    try {
        unsigned char opcode;
        s.Read(opcode);
        switch(opcode) {
        case 0:
            //Retrieve named object
            char* objName = s.ReadString();
            break;
        }
    }catch(const char* err) {

    }
}

int main(int argc, char** argv) {

    auto bot = [=](const char* txt){
        printf("%s\n",txt);
        return 5;
    };
    int(*fptr)(void*,const char*);
    void* thisptr = C(bot,fptr);
    int rval = fptr(thisptr,"Hi world!");
    printf("%i\n",rval);
    sleep(-1);
    return 0;

    printf("OpenNet -- Key generation in progress....\n");
db = OpenNet_OAuthInitialize();
printf("OpenNet -- System ready -- net init\n");
    GlobalGrid::P2PConnectionManager mngr;
GlobalGrid::InternetProtocol ip(5809,&mngr);
mngr.RegisterProtocol(&ip);
ReceiveCallback onReceived;
onReceived.onDestroyed = 0;
onReceived.onReceived = processRequest;
GlobalGrid_OpenPort(mngr.nativePtr,1,onReceived);
printf("OpenNet -- System active\n");
sleep(-1);
}
