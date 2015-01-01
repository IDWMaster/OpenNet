
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <OpenAuth.h>
#include <mutex>
#include <string>
#include "LightThread.h"
static size_t replicaCount = 0;

class BStream {
public:
    unsigned char* ptr;
    size_t length;
    BStream(unsigned char* buffer, size_t sz) {
        this->ptr = buffer;
        this->length = sz;
    }
    void Increment(size_t sz) {
    	if(sz>length) {
    		throw "up";
    	}
    	length-=sz;
    	ptr+=sz;
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
class Callback {
public:
	std::function<void(NamedObject*)> callback;
	bool* cancellationToken;
};
static std::mutex callbacks_mtx;
static std::map<std::string,Callback> callbacks;
static void* connectionmanager;
static void* db;

static void processRequest(void* thisptr, unsigned char* src, int32_t srcPort, unsigned char* data, size_t sz) {
    //Received a DNS request; process it
    BStream s(data,sz);
    try {
        unsigned char opcode;
        s.Read(opcode);
        switch(opcode) {
        case 0:
        {
            char* name = s.ReadString();
            printf("Request for %s\n",name);
            //GGDNS request entry
            void(*callback)(void*,NamedObject*);
            void* thisptr = C([&](NamedObject* obj){
                    //Found it!
                    size_t sz = 1+strlen(obj->authority)+strlen(name)+4+obj->bloblen+4+obj->siglen;
                    unsigned char* response = (unsigned char*)malloc(sz);
                    unsigned char* ptr = response;
                    *ptr = 1;
                    ptr++;
                    memcpy(ptr,obj->authority,strlen(obj->authority));
                    ptr+=strlen(obj->authority);
                    memcpy(ptr,name,strlen(name));
                    ptr+=strlen(name);
                    memcpy(ptr,&obj->bloblen,4);
                    ptr+=4;
                    memcpy(ptr,obj->blob,obj->bloblen);
                    ptr+=obj->bloblen;
                    memcpy(ptr,&obj->siglen,4);
                    ptr+=4;
                    memcpy(ptr,obj->signature,obj->siglen);

                    GlobalGrid_Send(connectionmanager,src,srcPort,1,response,sz);
                    free(response);
            },callback);
            OpenNet_Retrieve(db,name,thisptr,callback);
        }
            break;
        case 1:
        	NamedObject obj;
        	obj.authority = s.ReadString();
        	const char* name = s.ReadString();
        	printf("Received ACK for %s from %s\n",name,obj.authority);
        	uint32_t val;
        	s.Read(val);
        	obj.bloblen = val;
        	obj.blob = s.ptr;
        	s.Increment(val);
        	s.Read(val);
        	obj.siglen = val;
        	obj.signature = s.ptr;
        	s.Increment(val);
        	bool success = OpenNet_AddObject(db,name,&obj);
        	if(success) {
        		callbacks_mtx.lock();
        		if(callbacks.find(name) != callbacks.end()) {
        			Callback callback = callbacks[name];
        			CancelTimer(callback.cancellationToken);
        			callbacks_mtx.unlock();
        			callback.callback(&obj);

        		}else {
        			callbacks_mtx.unlock();
        		}
        	}
        	break;
        }
    }catch(const char* err) {

    }
}
template<typename F>
static void SendQuery(const char* name, const F& callback) {
	callbacks_mtx.lock();
	Callback cb;
	cb.callback = callback;
	cb.cancellationToken = CreateTimer([=](){callback(0);},5000);
	callbacks[name] = cb;
	callbacks_mtx.unlock();
    size_t namelen = strlen(name)+1;
    //OPCODE, name
    unsigned char* buffer = new unsigned char[1+namelen];
    unsigned char* ptr = buffer;
    *ptr = 0;
    ptr++;
    memcpy(ptr,name,namelen);
    GlobalGrid_Identifier* identifiers;
    size_t length = GlobalGrid_GetPeerList(connectionmanager,&identifiers);
    for(size_t i = 0;i<length;i++) {
        GlobalGrid_Send(connectionmanager,(unsigned char*)identifiers[i].value,1,1,buffer,1+namelen);
    }
    delete[] buffer;
}

template<typename F>
static void RunQuery(const char* name, const F& callback) {
    void(*functor)(void*,NamedObject*);
    bool m = false;
    auto bot = [&](NamedObject* obj) {
        m = true;
        callback(obj);
    };
    void* thisptr = C(bot,functor);
    OpenNet_Retrieve(db,name,thisptr,functor);
    if(!m) {
        //Send query
        SendQuery(name,callback);
    }
}
static void GGDNS_Initialize(void* manager) {
db = OpenNet_OAuthInitialize();
    ReceiveCallback onReceived;
    onReceived.onDestroyed = 0;
    onReceived.onReceived = processRequest;
    GlobalGrid_OpenPort(manager,1,onReceived);
    connectionmanager = manager;
}


extern "C" {
void GGDNS_Init(void* manager) {
    GGDNS_Initialize(manager);
}
void GGDNS_SetReplicaCount(size_t count) {
	replicaCount = count;
}
void GGDNS_EnumPrivateKeys(void* thisptr,bool(*enumCallback)(void*,const char*)) {
    OpenNet_OAuthEnumPrivateKeys(db,thisptr,enumCallback);
}

void GGDNS_MakeObject(const char* name, NamedObject* object, void* thisptr,  void(*callback)(void*,bool)) {
    OpenNet_MakeObject(db,name,object);
    if(callback) {
    callback(thisptr,true);
    }
}

void GGDNS_RunQuery(const char* name,void* thisptr, void(*callback)(void*,NamedObject*)) {
    RunQuery(name,[=](NamedObject* obj){
        callback(thisptr,obj);
    });
}
}
