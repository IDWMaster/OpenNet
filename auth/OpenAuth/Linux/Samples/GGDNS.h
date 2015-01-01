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
//servers asynchronously. The mandatory user-defined callback function will be invoked when the operation completes.
//The local dataset is consistent as soon as this function returns. Local disk updates are performed asynchronously; whereas
//replication is asynchronous.
void GGDNS_MakeObject(const char* name, NamedObject* object, void* thisptr,  void(*callback)(void*,bool));
//Sets the desired number of replicas for this dataset. Changing this number does NOT
//effect data already in the database. This only changes the number of replicas
//data will be written to before reporting a successful write. Data that is not
//successfully replicated will still be added to your local database instance,
//and may also be cached on other database servers if those objects are requested.
void GGDNS_SetReplicaCount(size_t count);
#ifdef __cplusplus
}
#endif
#endif // GGDNS_H
