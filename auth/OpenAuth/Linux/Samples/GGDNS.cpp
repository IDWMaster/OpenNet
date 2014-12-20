
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <OpenAuth.h>
#include <mutex>




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
class Download {
public:
    unsigned char* buffer;
    size_t len;
    Download(size_t len) {
        buffer = (unsigned char*)malloc(len);
        this->len = len;
    }
    ~Download() {
        free(buffer);

    }
};

static std::map<std::string,Download> partialDownloads;
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
            uint16_t blockID;
            s.Read(blockID);
            //Retrieve named object. A named object has properties such as the authority, signature, and length,
            //and the blob content is grouped into segments of 4KB each.
            //This call will retrieve all named attributes of the object, as well as the specified blob index
            //(where index = n*(4*1024)).
            //Systems with no prior knowledge of size should always request block 0 first.
            //The default limit on blob size is 1MB
            char* objName = s.ReadString();
            unsigned char* encodedObject;
            size_t total;
            auto enumCallback = [&](NamedObject* object){
                //authority, blob, bloblen, signature, siglen
                size_t objslen = strlen(objName)+1;
                size_t slen = strlen(object->authority)+1;
                size_t dataLen = std::min(object->bloblen,(size_t)(1024*4));
                total = 1+2+objslen+slen+4+object->bloblen+4+object->siglen+dataLen;
                encodedObject = (unsigned char*)malloc(total);
                unsigned char* ptr = encodedObject;
                *ptr = 1;
                ptr++;
                memcpy(ptr,&blockID,2);
                ptr+=2;
                memcpy(ptr,objName,objslen);
                ptr+=objslen;
                memcpy(ptr,object->authority,slen);
                ptr+=slen;
                //On 64-bit systems this will truncate; but it's OK in most cases.
                //Unless running on a very strange processor it won't cause any problems.
                memcpy(ptr,&object->bloblen,4);
                ptr+=4;
                memcpy(ptr,&object->siglen,4);
                ptr+=4;
                memcpy(ptr,object->signature,object->siglen);
                ptr+=object->siglen;
                //Get block
                unsigned char* addr = (blockID*(1024*4))+object->blob;
                if(addr+dataLen>object->blob+dataLen) {
                    //Overflow; respawn
                    addr = object->blob;
                }
                //Write data into the blob
                memcpy(ptr,addr,dataLen);
            };
            //Convert to C-style function pointer
            void(*functor)(void*,NamedObject*);
            void* thisptr = C(enumCallback,functor);
            OpenNet_Retrieve(db,objName,thisptr,functor);
            if(encodedObject) {
            GlobalGrid_Send(connectionmanager,src, 1,srcPort,encodedObject,total);
            }else {
                unsigned char* mander = (unsigned char*)(objName-1);
                *mander = 1;
                GlobalGrid_Send(connectionmanager,src,1,srcPort,mander,2+strlen((char*)(mander+1)));
            }
            free(encodedObject);
        }
            break;
        case 1:
            {
            //Packet structure: OPCODE (byte), ,  Object name (string), Block identifier (int16)
            //Authority thumbprint (string), Blob length (Int32)
            //SigLen (int32), Signature (byte[]), Block (byte[])
            char* objName = s.ReadString();
            if(s.length) {
                printf("%s found.\n",objName);
            }else {
                printf("%s was not found on the requested server.\n",objName);
            }
            }
            break;
        }
    }catch(const char* err) {

    }
}

static void SendQuery(const char* name, uint16_t blockID) {
    size_t namelen = strlen(name)+1;
    //OPCODE, blockID, name
    unsigned char* buffer = new unsigned char[1+2+namelen];
    unsigned char* ptr = buffer;
    *ptr = 0;
    ptr++;
    memcpy(ptr,&blockID,2);
    ptr+=2;
    memcpy(ptr,name,namelen);
    GlobalGrid_Identifier* identifiers;
    size_t length = GlobalGrid_GetPeerList(connectionmanager,&identifiers);
    for(size_t i = 0;i<length;i++) {
        GlobalGrid_Send(connectionmanager,(unsigned char*)identifiers[i].value,1,1,buffer,1+2+namelen);
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
    if(!m) {
        //Send query
        SendQuery(name,0);
    }
    void* thisptr = C(bot,functor);
    OpenNet_Retrieve(db,name,thisptr,functor);
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
}
