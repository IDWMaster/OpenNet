#ifndef GGDNS_H
#define GGDNS_H
#include <OpenAuth.h>
#ifdef __cplusplus
extern "C" {
#endif
//Initializes GGDNS
void GGDNS_Init(void* mngr);
void GGDNS_RunQuery(const char* name,void* thisptr, void(*callback)(void*,NamedObject*));
void GGDNS_EnumPrivateKeys(void* thisptr,bool(*enumCallback)(void*,const char*));
//Adds an object to the local database and attempts to replicate it to the desired number of replica
//servers asynchronously. The optional callback is invoked when replication completes or times out.
void GGDNS_MakeObject(const char* name, NamedObject* object, void* thisptr,  void(*callback)(void*,bool));
//Sets the desired number of replicas for this dataset. Changing this number does NOT
//effect data already in the database. This only changes the number of replicas
//data will be written to before reporting a successful write. Data that is not
//successfully replicated will still be added to your local database instance,
//and may also be cached on other database servers if those objects are requested.
void GGDNS_SetReplicaCount(size_t count);
void GGDNS_QueryDomain(const char* name, const char* parent, void* tptr, void(*callback)(void*,const char*));
void GGDNS_GetGuidListForObject(const char* objid,void* thisptr, void(*callback)(void*,unsigned char*,size_t));
void GGDNS_SetTimeoutInterval(size_t ms);
void GGDNS_MakeDomain(const char* name, const char* parent,  const char* authority,void* thisptr, void(*callback)(void* thisptr, unsigned char* data, size_t dlen));
//Modifies the host list for a domain name under your control (where ptr is the pointer to your domain)
//Length is the length (in bytes) of the guidlist. A guidlist should
//be composed of individual 16-byte entries.
void GGDNS_MakeHost(const char* ptr, unsigned char* guidlist, size_t len);
void* GGDNS_db();
#ifdef __cplusplus
}
#endif


#ifdef __cplusplus
//TODO: C++ helpers
static std::string DotQuery(const char* query) {
	auto expect = [](const char*& str, const char& value, bool& found){
		size_t offset = 0;
		found = false;
		while(*(str+offset) != 0) {
			if(*(str+offset) == value) {
				//TODO: Take substring
				str = str+offset+1;
				found = true;
				return std::string(str,offset);
			}
			offset++;
		}
		return std::string(str);
	};
	std::vector<std::string> components;
	bool found = true;
	while(true) {
		components.push_back(expect(query,'.',found));
		if(!found) {
			break;
		}
	}
	std::string parent;
	for(size_t i = components.size()-1;i>=0;i--) {
		Event m;
		void(*cb)(void*,const char*);
		void* thisptr = C([&](const char* name){
			parent = name;
			m.signal();
		},cb);
		GGDNS_QueryDomain(components[i].data(),parent.data(),thisptr,cb);
		m.wait();
	}
	return parent;
}
#endif

#endif // GGDNS_H
