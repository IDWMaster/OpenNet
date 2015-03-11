#define charmander char mander
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <OpenAuth.h>
#include <mutex>
#include <string>
#include "LightThread.h"
#include <uuid/uuid.h>
#include "GGDNS.h"
#include <memory>
static size_t timeoutValue = 5000;
static void sendObjectTo(const char* name, unsigned char* dest);
class BStream {
public:
    unsigned char* ptr;
    size_t length;
    BStream(unsigned char* buffer, size_t sz) {
        this->ptr = buffer;
        this->length = sz;
    }
    unsigned char* Increment(size_t sz) {
    	unsigned char* retval = ptr;
    	if(sz>length) {
    		throw "up";
    	}
    	length-=sz;
    	ptr+=sz;
    	return retval;
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
        charmander;
        while(Read(mander) != 0){}
        return retval;
    }
};
class WaitHandle {
public:
	//The event
	Event evt;
	//Whether or not it was successful
	bool success;
	WaitHandle() {
		success = false;
	}
};
static std::mutex callbacks_mtx;
//Resolver cache; used to map GUIDs to server identifiers
static std::map<std::string,std::vector<GlobalGrid_Identifier>> resolverCache;
static std::map<std::string,std::shared_ptr<WaitHandle>> objectRequests;
static std::map<std::string,std::shared_ptr<WaitHandle>> certRequests;
static void* connectionmanager;
static void* db;
static void SendQuery_Raw(const char* name);
template<typename F>
static void RunQuery(const char* _name, const F& callback);
static void processDNS(const char* name) {
	try {
	//Attempt to insert/update DNS record
	void(*callback)(void*,NamedObject*);
	void* thisptr;
	std::vector<unsigned char> data;
	std::string authority;
	auto bot = [&](NamedObject* obj){
		if(obj) {
			data.resize(obj->bloblen-4);
			memcpy(data.data(),obj->blob+4,data.size());
			authority = obj->authority;
		}
	};
	thisptr = C(bot,callback);
	OpenNet_Retrieve(db,name,thisptr,callback);

	if(data.size()) {
		BStream s(data.data(),data.size());
		//Read DNS-ENC marker
		char* header = s.ReadString();
		if(std::string("DNS-ENC") == header) {
			//DNS name
			const char* dname = s.ReadString();
			if(strlen(dname) == 0) {
				return;
			}
			//DNS parent
			const char* parent = s.ReadString();
			//DNS owner
			const char* owner = s.ReadString();
			//Signature (proof of ownership)
			size_t siglen = s.length;
			unsigned char* sig = s.Increment(s.length);
			bool verified = OpenNet_VerifySignature(db,owner,data.data(),data.size()-siglen,sig,siglen);
			if(!verified) {
				return;
			}
			//WE HAVE DNS!!!!
			//TODO: Verify signature matches and add to database
			//If we don't have signatures for parent zone; request them, then
			//resend this request recursively.
			if(strlen(parent) == 0) {
				//We are root; add directly to database.
				OpenNet_AddDomain(db,dname,0,name);
			}else {
				//TODO: We are NOT root. Load parent node and check signature

				std::string parentAuthority;
				std::string parent_name = parent;
				auto m = [&](NamedObject* obj){
					parentAuthority = obj->authority;
				};
				void(*cb)(void*,NamedObject*);
				void* thisptr = C(m,cb);
				GGDNS_RunQuery(parent_name.data(),thisptr,cb); //TODO: Possible deadlock here
				if(parentAuthority.size()) {
					if(parentAuthority == authority) {
						void(*t_cb)(void*,const char*,const char*);
						void* t_a = C([&](const char* a,const char* b){
							//WE'RE VERIFIED
							OpenNet_AddDomain(db,dname,parent,name);
						},t_cb);

						OpenNet_FindReverseDomain(db,parent_name.data(),t_a,t_cb);

					}else {
						//Fail. Bad authority (mismatch).
						return;
					}
				}else {
					//Fail
					return;
				}

			}
		}else {
			if(std::string("DNS-ID") == header) {
				//DNS-encoded ID (host information)

				char* id = s.ReadString();

				void* thisptr;
				void(*cb)(void*,const char*,const char*);
				bool hasValidDomain = false;
				thisptr = C([&](const char* name, const char* parent){
					hasValidDomain = true;
				},cb);

				OpenNet_FindReverseDomain(db,id,thisptr,cb);
				if(hasValidDomain) {
					//Check if signature matches authority

					void* tptr;
					void(*r_cb)(void*,NamedObject*);
					bool sigMatches = false;
					tptr = C([&](NamedObject* obj){
						BStream dreader(obj->blob,obj->bloblen);
						dreader.ReadString();
						dreader.ReadString();
						dreader.ReadString();

						if(authority == dreader.ReadString()) {
							sigMatches = true;
						}
					},r_cb);
					GGDNS_RunQuery(id,tptr,r_cb);
					if(sigMatches) {
						OpenNet_AddDomainPtr(db,id,name);
					}
				}
			}
		}
	}
	}catch(const char* er) {

	}
}

class CallOnReturn {
public:
	std::function<void()> function;
	CallOnReturn(const std::function<void()>& functor):function(functor) {
	}
	~CallOnReturn() {
		function();
	}
};
static void processRequest(void* thisptr_, unsigned char* src_, int32_t srcPort, unsigned char* data_, size_t sz) {
    //Received a DNS request; process it
	unsigned char* data = new unsigned char[sz];
	unsigned char src[16];
	memcpy(data,data_,sz);
	memcpy(src,src_,16);
	SubmitWork([=](){
		//TODO: Ensure that data gets freed in all cases
		void* thisptr;
		CallOnReturn freer([&](){
			delete[] data;
		});
		 BStream s(data,sz);
		    try {
		        unsigned char opcode;
		        s.Read(opcode);
		        switch(opcode) {
		        case 0:
		        {
		            char* name = s.ReadString();

		            //GGDNS request entry
		            void(*callback)(void*,NamedObject*);
		            void* thisptr = C([&](NamedObject* obj){
		                    //Found it!
		                    size_t sz = 1+strlen(obj->authority)+1+strlen(name)+1+4+obj->bloblen+4+obj->siglen;
		                    unsigned char* response = (unsigned char*)malloc(sz);
		                    unsigned char* ptr = response;
		                    *ptr = 1;
		                    ptr++;
		                    memcpy(ptr,obj->authority,strlen(obj->authority)+1);
		                    ptr+=strlen(obj->authority)+1;
		                    memcpy(ptr,name,strlen(name)+1);
		                    ptr+=strlen(name)+1;
		                    memcpy(ptr,&obj->bloblen,4);
		                    ptr+=4;
		                    memcpy(ptr,obj->blob,obj->bloblen);
		                    ptr+=obj->bloblen;
		                    memcpy(ptr,&obj->siglen,4);
		                    ptr+=4;
		                    memcpy(ptr,obj->signature,obj->siglen);
		                    GlobalGrid_Send(connectionmanager,(unsigned char*)src,srcPort,1,response,sz);
		                    free(response);
		            },callback);
		            OpenNet_Retrieve(db,name,thisptr,callback);
		        }
		            break;
		        case 1:
		        {
		        	NamedObject obj;
		        	obj.authority = s.ReadString();
		        	const char* name = s.ReadString();
		        	uint32_t val;
		        	s.Read(val);
		        	obj.bloblen = val;
		        	obj.blob = s.Increment(val);
		        	s.Read(val);
		        	obj.siglen = val;
		        	obj.signature = s.Increment(val);
		        	bool replace = false;
		        	uint32_t objVersion;
		        	uint32_t oldVersion;
		        	memcpy(&oldVersion,obj.blob,4);
		        	void(*c)(void*, NamedObject*);
		        	std::string oldauth;
		        	auto cvi = [&](NamedObject* obj){
		        		if(obj) {
		        			replace = true;
		        			memcpy(&objVersion,obj->blob,4);
		        			oldauth = obj->authority;
		        		}
		        	};
		        	if(objVersion <=oldVersion) {
		        		return;
		        	}
		        	void* tp = C(cvi,c);
		        	OpenNet_Retrieve(db,name,tp,c);
		        	if(obj.bloblen<4 || (oldauth != obj.authority && replace)) {
		        	        		return;
		        	        	}
		        	bool success = false;
		        	if(replace) {
		        		success = OpenNet_UpdateObject(db,name,&obj);
		        	}else {
		        		success = OpenNet_AddObject(db,name,&obj);
		        	}
		        	if(success) {
		        		processDNS(name);
		        		OpenNet_AddReplica(db,name,src);
		        		callbacks_mtx.lock();
		        		if(objectRequests.find(name) != objectRequests.end()) {
		        			std::shared_ptr<WaitHandle> callback = objectRequests[name];
		        			callbacks_mtx.unlock();
		        			callback->success = true;
		        			callback->evt.signal();
		        		}else {
		        			callbacks_mtx.unlock();
		        		}
		        	}else {
		        			//TODO: Failed to add object. Likely signature check failed.
		        			//Request a copy of the digital signature.


	                    std::cerr<<"RECV: SIG CHECK ERR AUTH "<<obj.authority<<std::endl;
		        		std::shared_ptr<WaitHandle> ccb = std::make_shared<WaitHandle>();

		        		std::string auth = obj.authority;
		        		std::string objname = name;
	        			size_t len = 1+strlen(obj.authority)+1;
	        			unsigned char* packet = (unsigned char*)alloca(len);
	        			unsigned char* ptr = packet;
	        			*ptr = 2;
	        			ptr++;
	        			memcpy(ptr,obj.authority,strlen(obj.authority)+1);
	        			ptr+=strlen(obj.authority)+1;
	        			std::cerr<<"Sent CERT request for "<<obj.authority<<std::endl;
	        				GlobalGrid_Send(connectionmanager,(unsigned char*)src,1,1,packet,len);

		        		std::shared_ptr<TimerEvent> timer = CreateTimer([=](){
		        			ccb->evt.signal();
		        		},timeoutValue);
		        		ccb->evt.wait();
		        		//TODO: Possible problem here if timer has already gone off.
		        		CancelTimer(timer);
		        		if(ccb->success) {
		        			//Resend request if successful
		        			SendQuery_Raw(objname.data());
		        		}
		        		std::cerr<<"Lock acquire\n";
		        		callbacks_mtx.lock();

		        		certRequests[obj.authority] = ccb;
		        			callbacks_mtx.unlock();
		        			std::cerr<<"Lock release\n";

		        	}
		        }
		        	break;
		        case 2:
		        {
		        	//TODO: Process Received certificate request
		        	const char* authority = s.ReadString();
		        	std::cerr<<"Authority request for "<<authority<<std::endl;
		        	void(*callback)(void* thisptr, OCertificate* cert);
		        	thisptr = C([&](OCertificate* cert){
		        		if(cert) {
		                	size_t sz = 1+strlen(cert->authority)+1+4+cert->siglen+4+cert->pubLen;
		                	unsigned char* packet = (unsigned char*)alloca(sz);
		                	unsigned char* ptr = packet;
		                	*ptr = 3;
		                	ptr++;
		                	memcpy(ptr,cert->authority,strlen(cert->authority)+1);
		                	ptr+=strlen(cert->authority)+1;
		                	memcpy(ptr,&cert->siglen,4);
		                	ptr+=4;
		                	memcpy(ptr,cert->signature,cert->siglen);
		                	ptr+=cert->siglen;
		                	memcpy(ptr,&cert->pubLen,4);
		                	ptr+=4;
		                	memcpy(ptr,cert->pubkey,cert->pubLen);
		                	GlobalGrid_Send(connectionmanager,(unsigned char*)src,srcPort,1,packet,sz);
		        		}
		        	},callback);
		        	OpenNet_RetrieveCertificate(db,authority,thisptr,callback);

		        }
		        break;
		        case 3:
		        {
		        	//Received certificate information
		        	OCertificate cert;
		        	cert.authority = s.ReadString();
		        	uint32_t len;
		        	s.Read(len);
		        	cert.siglen = len;
		        	cert.signature = s.Increment(len);
		        	s.Read(len);
		        	cert.pubLen = len;
		        	cert.pubkey = s.Increment(len);
		        	void(*callback)(void*,const char*);
		        	std::shared_ptr<WaitHandle> cb;
		        	bool found = false;
		        	thisptr = C([&](const char* thumbprint){
		        		if(thumbprint == 0) {
		        			return;
		        		}
		        		callbacks_mtx.lock();
		        		if(certRequests.find(thumbprint) != certRequests.end()) {
		        			cb = certRequests[thumbprint];
		        			callbacks_mtx.unlock();
		        			found = true;
		        		}else {
		        			callbacks_mtx.unlock();
		        		}
		        	},callback);
		        	OpenNet_AddCertificate(db,&cert,thisptr,callback);
		        	if(found) {
		        		cb->success = true;
		        		cb->evt.signal();
		        	}
		        }
		        	break;
		        case 4:
		        {
		        	//DNS resolution request (similar to New Year's resolution)
		        	const char* dns_name = s.ReadString();
		        	const char* dns_parent = s.ReadString();
		        	std::string name;
		        	auto bot = [&](const char* objname){
		        		if(objname) {
		        			name = objname;
		        		}
		        	};
		        	void(*callback)(void*,const char*);
		        	void* thisptr = C(bot,callback);
		        	OpenNet_FindDomain(db,dns_name,dns_parent,thisptr,callback);
		        	if(name.size()) {
		        		//Fake a query to our own server to search for the object BLOB
		        		unsigned char* request = (unsigned char*)alloca(1+name.size()+1);
		        		*request = 0;
		        		memcpy(request+1,name.data(),name.size()+1);
		        		processRequest(0,(unsigned char*)src,srcPort,request,1+name.size()+1);

		        	}
		        }
		        	break;
		        case 5:
		        	break; //TODO: Uncomment this line to enable DMCA takedown compliance toolkit
		        	//TODO: DMCA takedown request; only process if signed by valid DMCA authority
		        	char* authority = s.ReadString();
		        	uint32_t reqlen;
		        	s.Read(reqlen);
		        	//Create virtual cryptographic "buffer"
		        	unsigned char* cryptBuffer = s.Increment(reqlen);
		        	uint32_t slen;
		        	s.Read(slen);
		        	unsigned char* sigBuffer = s.Increment(slen);
		        	unsigned char pubkey[] = {0, 0, 0, 0, 0}; //put DMCA authority public key here
		        	if(authority == "TODO: PUT DMCA AGENT STRING HERE") {

		        		if(VerifySignature(cryptBuffer,reqlen,sigBuffer,slen,pubkey)) {
		        			//Process takedown request
		        			BStream k(cryptBuffer,reqlen);
		        			char* blobID = k.ReadString();
		        			DMCA_TakedownBlob(db,blobID); //TODO: Implement this
		        		}
		        	}
		        	break;
		        }
		    }catch(const char* err) {

		    }
	});

}
static void SendQuery_Raw(const char* name) {
	//OPCODE, name

    	size_t namelen = strlen(name)+1;
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
static void RunQuery(const char* _name, const F& callback);
template<typename F>
static void SendQuery(const char* name, const F& callback) {

	std::shared_ptr<WaitHandle> cb = std::make_shared<WaitHandle>();
	CreateTimer([=](){cb->evt.signal();},timeoutValue);
	callbacks_mtx.lock();
	objectRequests[name] = cb;
	callbacks_mtx.unlock();

    SendQuery_Raw(name);
    cb->evt.wait();
    if(cb->success) {
    	void(*cb)(void*,NamedObject*);
    	void* thisptr = C([&](NamedObject* obj){
    		callback(obj);
    	},cb);
    	GGDNS_RunQuery(name,thisptr,cb);
    	}else {
    		callback(0);
    	}
}

template<typename F>
static void RunQuery(const char* _name, const F& callback) {
    void(*functor)(void*,NamedObject*);
    bool m = false;
    std::string name = _name;
    auto invokeCallback = [=](NamedObject* obj) {
    	callbacks_mtx.lock();
    	if(objectRequests.find(name) != objectRequests.end()) {
    		objectRequests.erase(name);
    	}
    	callbacks_mtx.unlock();
    	if(obj) {
    	obj->blob+=4;
    	obj->bloblen-=4;
    	}
    	callback(obj);
    };
    auto bot = [&](NamedObject* obj) {


        m = true;
        invokeCallback(obj);
    };
    void* thisptr = C(bot,functor);
    OpenNet_Retrieve(db,name.data(),thisptr,functor); //TODO: Not a deadlock. It's just NOT finding the object for some reason!
    if(!m) {
        //Send query
        SendQuery(name.data(),invokeCallback);
    }else {
    	SendQuery_Raw(name.data());
    }
}

static void sendObjectTo(const char* name, unsigned char* dest) {
	size_t len = 1+strlen(name)+1;
	unsigned char* msg = new unsigned char[len];
	*msg = 0;
	memcpy(msg+1,name,strlen(name));
	processRequest(0,dest,1,msg,len);
	GlobalGrid_Send(connectionmanager,dest,1,1,msg,len);
	delete[] msg;


}
static void replicate() {
	void* thisptr;
	bool(*cb)(void*,const char*);
	std::vector<std::string> toBeContinued;
	thisptr = C([&](const char* name){
		toBeContinued.push_back(name);
		return true;
	},cb);
	OpenNet_GetMissingReplicas(db,thisptr,cb);

	for(size_t i = 0;i<toBeContinued.size();i++) {

		std::string stackstring = toBeContinued[i];
		std::cerr<<stackstring<<std::endl;

		//TODO: Get the replica set information
		std::string parentDomain;
		void* thisptr_;
		void(*cb_)(void*,const char*,const char*);
		thisptr = C([&](const char* name, const char* parentID){
			if(parentID) {
				parentDomain = parentID;
			}
		},cb_);
		OpenNet_FindReverseDomain(db,stackstring.data(),thisptr_,cb_);
		if(parentDomain.size()) {
			//We have child authoritative domain
			unsigned char* guidlist = 0;
			size_t gsize = 0;
			void *thisptr__ ;
			void(*cb__)(void*,unsigned char*,size_t);
			thisptr__ = C([&](unsigned char* list,size_t bytes){
				if(bytes % 16 == 0) {
				guidlist = new unsigned char[bytes];
				gsize = bytes;
				memcpy(guidlist,list,bytes);
				}
			},cb__);
			 GGDNS_GetGuidListForObject(parentDomain.data(),thisptr__,cb__);

			 if(guidlist) {
				 for(size_t c = 0;c<gsize;c+=16) {
					 sendObjectTo(stackstring.data(),guidlist+c);
				 }
				 delete[] guidlist;
			 }

		}



		GlobalGrid_Identifier* list;
		size_t glen = GlobalGrid_GetPeerList(connectionmanager,&list);
		for(size_t i = 0;i<glen;i++) {
			processRequest(0,(unsigned char*)(list+i),1,izard,reqsz);
		}
		GlobalGrid_FreePeerList(list);


	}


}


static void GGDNS_Initialize(void* manager) {
db = OpenNet_OAuthInitialize();
    ReceiveCallback onReceived;
    onReceived.onDestroyed = 0;
    onReceived.onReceived = processRequest;
    GlobalGrid_OpenPort(manager,1,onReceived);
    connectionmanager = manager;

    RetryOperation([](std::function<void()> completion){
    	replicate();
    },800,-1,[=](){});
    GGDNS_SetReplicaCount(1);
}


extern "C" {
void GGDNS_MakeObject(const char* name, NamedObject* object, void* thisptr,  void(*callback)(void*,bool));
void GGDNS_Init(void* manager) {
    GGDNS_Initialize(manager);
}
void GGDNS_SetReplicaCount(size_t count) {
	OpenNet_replicaCount = count;
}
void GGDNS_EnumPrivateKeys(void* thisptr,bool(*enumCallback)(void*,const char*)) {
    OpenNet_OAuthEnumPrivateKeys(db,thisptr,enumCallback);
}
void GGDNS_QueryDomain(const char* name, const char* parent, void* tptr, void(*callback)(void*,const char*)) {
	//OPCODE 4
	size_t allocsz = 1+strlen(name)+1+strlen(parent)+1;
	unsigned char* request = (unsigned char*)alloca(allocsz);
	*request = 4;
	memcpy(request+1,name,strlen(name)+1);
	memcpy(request+1+strlen(name)+1,parent,strlen(parent));
	//Check local database
	std::string objid;
	auto bot = [&](const char* dname) { //called dname JUST to confuse all those database students
		objid = dname;
	};
	void(*cb)(void*,const char*);
	void* thisptr = C(bot,cb);
	OpenNet_FindDomain(db,name,parent,thisptr,cb);
	if(objid.size()) {
		callback(tptr,objid.data());
	}else {
		//TODO: Send request
		GlobalGrid_Identifier* list;
		size_t count = GlobalGrid_GetPeerList(connectionmanager,&list);
		for(size_t i = 0;i<count;i++) {
			GlobalGrid_Send(connectionmanager,(unsigned char*)list[i].value,1,1,request,allocsz);
		}
		GlobalGrid_FreePeerList(list);
		//IF we know that a given peer is authoritative for a parent; send it there as well
		std::vector<GlobalGrid_Identifier> ids;
		callbacks_mtx.lock();
		if(resolverCache.find(parent) != resolverCache.end()) {
			ids = resolverCache[parent];
		}
		callbacks_mtx.unlock();
		for(size_t i = 0;i<ids.size();i++) {
			GlobalGrid_Send(connectionmanager,(unsigned char*)ids[i].value,1,1,request,allocsz);
		}
		callback(tptr,0);
	}
}
void GGDNS_SetTimeoutInterval(size_t ms) {
	timeoutValue = ms;
}
void GGDNS_GetGuidListForObject(const char* objid,void* thisptr, void(*callback)(void*,unsigned char*,size_t)) {
	std::string name = objid;
	//Query for the GUID list, and then use that object to enumerate
	void* ta;
	void(*ca)(void*,NamedObject*);
	ta = C([&](NamedObject* obj){
		if(obj){
			BStream reader(obj->blob,obj->bloblen);
			reader.ReadString();
			reader.ReadString();
			callback(thisptr,reader.ptr,reader.length);
		}
	},ca);
	OpenNet_RetrieveDomainPtr(db,objid,ta,ca);

}


void GGDNS_MakeHost(const char* ptr, unsigned char* guidlist, size_t len) {
	NamedObject obj;
	unsigned char* mander = new unsigned char[7+strlen(ptr)+1+len];
	memcpy(mander,"DNS-ID",7);
	memcpy(mander+7,ptr,strlen(ptr)+1);
	memcpy(mander+7+strlen(ptr)+1,guidlist,len);
	obj.blob = mander;
	obj.bloblen = 7+strlen(ptr)+1+len;
	std::string authority;
	void* thisptr;
	void(*cb)(void*,NamedObject*);
	thisptr = C([&](NamedObject* objPtr){
		authority = objPtr->authority;
	},cb);
	OpenNet_Retrieve(db,ptr,thisptr,cb);
//TODO: Finish creation of object, and add to some metadata base
	obj.authority = (char*)authority.data();
	unsigned char id[16];
	char txt[256];
	uuid_generate(id);
	uuid_unparse(id,txt);
	GGDNS_MakeObject(txt,&obj,0,0);

}

//Makes a domain entry pointing to an authoritative entity.
//This contains no additional information than the name and signature of
//the entity owning it. It must be signed by an authoritative server (in parent) to be valid
//Or; in the case of a root-level domain, must be self-signed using the signRecord command.
void GGDNS_MakeDomain(const char* name, const char* parent, const char* authority,void* thisptr, void(*callback)(void* thisptr, unsigned char* data, size_t dlen)) {

	unsigned char mid[16];
	GlobalGrid_GetID(connectionmanager,mid);
	char mid_s[256];
	uuid_unparse(mid,mid_s);
	size_t auth_sz = strlen("DNS-ENC")+1+strlen(name)+1+strlen(parent)+1+strlen(authority)+1;

	unsigned char* mander = new unsigned char[auth_sz];
	unsigned char* izard = mander;
	size_t s = strlen("DNS-ENC")+1;
	//DNS-ENC
	memcpy(izard,"DNS-ENC",s);
	izard+=s;
	//DNS name
	s = strlen(name)+1;
	memcpy(izard,name,s);
	izard+=s;
	//DNS parent
	s = strlen(parent)+1;
	memcpy(izard,parent,s);
	izard+=s;
	//Authority
	s = strlen(authority)+1;
	memcpy(izard,authority,s);
	izard+=s;
	//TODO: Signature
	unsigned char* sig;
	size_t sig_len;
	void(*cb)(void*,unsigned char*,size_t);
	void* thisptr_a = C([&](unsigned char* data,size_t siglen){
		sig = new unsigned char[siglen];
		memcpy(sig,data,siglen);
		sig_len = siglen;
	},cb);
	OpenNet_SignData(db,authority,mander,auth_sz,thisptr_a,cb);
	unsigned char* rval = new unsigned char[sig_len+auth_sz];
	memcpy(rval,mander,auth_sz);
	memcpy(rval+auth_sz,sig,sig_len);
	callback(thisptr,rval,sig_len+auth_sz);
	delete[] rval;
	delete[] sig;
}
void* GGDNS_db() {
	return db;
}

void GGDNS_MakeObject(const char* name, NamedObject* object, void* thisptr,  void(*callback)(void*,bool)) {
    uint32_t revisionID = 0;
    void(*cm)(void*,NamedObject*);
    NamedObject* val = 0;
    auto bot = [&](NamedObject* obj){
    	if(obj) {
    		val = obj;
    		memcpy(&revisionID,obj->blob,4);
    		revisionID++;
    	}
    };
    void* tp = C(bot,cm);
    OpenNet_Retrieve(db,name,tp,cm);
    unsigned char* data = new unsigned char[object->bloblen+4];
    memcpy(data,&revisionID,4);
    memcpy(data+4,object->blob,object->bloblen);
    NamedObject ival = *object;
    ival.blob = data;
    ival.bloblen = object->bloblen+4;
    ival.siglen = 0;
    ival.signature = 0;

    OpenNet_MakeObject(db,name,&ival,val);
    processDNS(name);

    replicate();
    *object = ival;
    delete[] data;
}

void GGDNS_RunQuery(const char* name,void* thisptr, void(*callback)(void*,NamedObject*)) {
    RunQuery(name,[=](NamedObject* obj){
        callback(thisptr,obj);
    });
}
}
