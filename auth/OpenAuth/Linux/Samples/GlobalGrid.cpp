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

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64
#include <iostream>
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <GGDNS.h>
#include <string>
#include <OpenAuth.h>
#include <uuid/uuid.h>

#include <functional>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include "LightThread.h"
#include <memory>
#include <fuse/fuse.h>
#include <errno.h>
//FS BEGIN

template<typename F, typename... args>
static void CallHeapFunction(void* val, args... uments) {
	(*((F*)val))(uments...);
	delete (F*)val;
}
template<typename T, typename... args>
static void* MakeHeapFunction(const T& val, void(*&callback)(void*,args...)) {
	callback = &CallHeapFunction<T,args...>;
	return new T(val);
}

class FS_Stream {
public:
	unsigned char start[16];
	uint32_t sector_size;
	unsigned char key[32];
	EVP_CIPHER_CTX enc;
	EVP_CIPHER_CTX dec;
	//XORs a block with a specified sector ID and sub-block ID (in GUID binary format)
	void XORBlock(unsigned char* block, unsigned char* src) {
		uint64_t alignedDest[512];
		uint64_t alignedSrc[2];
		memcpy(alignedDest,block,4096);
		memcpy(alignedSrc,src,16);
		for(size_t i = 0;i<512;i++) {
			alignedDest[i] ^= alignedSrc[i % 2] ^ i;
		}
		memcpy(block,alignedDest,4096);
	}
	template<typename F>
	void Sector_Read(const std::string& id, const F& callback) {
		void(*cb)(void* thisptr,NamedObject* obj);
		void* thisptr = MakeHeapFunction([=](NamedObject* obj){
			if(obj) {
				if(obj->bloblen != 4096) {
					//Illegal/invalid block length
					unsigned char mander[4096];
					memset(mander,0,4096);
					callback(mander);
				}else {
					//Decrypt
					int len = 4096;
					EVP_DecryptUpdate(&dec,obj->blob,&len,obj->blob,4096);
					unsigned char mid[16];
					uuid_parse(id.data(),mid);
					XORBlock(obj->blob,mid);
				}
			}else {
				unsigned char mander[4096];
				memset(mander,0,4096);
				callback(mander);
			}
		},cb);
		GGDNS_RunQuery(id.data(),thisptr,cb);
	}
	void Sector_Write(const std::string& id, const unsigned char* data) {
		unsigned char izard[4096];
		memcpy(izard,data,4096);
		unsigned char mid[16];
		uuid_parse(id.data(),mid);
		XORBlock(izard,mid);
		int l = 4096;
		EVP_EncryptUpdate(&enc,izard,&l,data,4096);
		NamedObject obj;
		//TODO: Later; add a callback which can be used to test when writes have finished replicating
		GGDNS_MakeObject(id.data(),&obj,0,0);

	}
	template<typename T>
	void ReadBlock(uint64_t offset, const T& callBach) {
		uint64_t sectorID = offset / 4096;
		uint64_t sectorOffset = offset % 4096;
		uint64_t rawID[2];
		memcpy(rawID,start,16);
		rawID[1] ^= sectorID;
		char mander[256];
		uuid_unparse((unsigned char*)rawID,mander);
		Sector_Read(mander,[=](unsigned char* izard){
			callBach(izard+sectorOffset);
		});
	}
	void WriteBlock(uint64_t offset, const unsigned char* data) {
		uint64_t sectorID = offset / 4096;
		uint64_t sectorOffset = offset % 4096;
		uint64_t rawID[2];
		memcpy(rawID,start,16);
		rawID[1] ^= sectorID;
		char mander[256];
		uuid_unparse((unsigned char*)rawID,mander);
		Sector_Write(mander,data);
	}
	class HeapStats {
	public:
		uint64_t offset;
		uint64_t count;
		unsigned char* dptr;
		std::function<void(unsigned char*)> cb;
	};
	template<typename T>
	void Read(uint64_t offset, uint64_t count, const T& callBeethoven) {
		unsigned char* mander = new unsigned char[count];
		auto heapStats = new HeapStats();
		heapStats->count = count;
		heapStats->offset = offset;
		heapStats->dptr = mander;
		auto bot = [=](unsigned char* sector) {

			uint64_t alignOffset = heapStats->offset % 4096;
			uint64_t avail = std::min(heapStats->count,4096-alignOffset);
			memcpy(heapStats->dptr,sector+alignOffset,avail);
			heapStats->count-=avail;
			heapStats->offset+=avail;
			if(heapStats->count == 0) {
				//Call up the dead guy who's decomposing a TON of music
				//(MUCH more accomplished than Bach ever was!)
				callBeethoven(mander);
				delete heapStats;
				delete[] mander;
			}else {
				ReadBlock((heapStats->offset/4096)*4096,heapStats->cb);
			}
		};
		heapStats->cb = bot;
		ReadBlock((offset/4096)*4096,bot);
	}
	void Write(uint64_t offset, uint64_t count, unsigned char* mander) {
		while(count>0) {
			uint64_t alignedSector = (offset/4096)*4096;
			uint64_t alignment = offset % 4096;
			uint64_t avail = std::min(4096-alignment,count);
			//TODO: Finish this
			unsigned char sector[4096];
			if(alignment) {
				Event evt;
				ReadBlock(alignedSector,[&](unsigned char* c_c){
					memcpy(sector,c_c,4096);
					evt.signal();
				});
				evt.wait();
			}
			memcpy(sector+alignment,mander,avail);
			//Write sector to disk -- replication happens asynchronously and is invisible to the application
			WriteBlock(alignedSector,sector);
		}
	}

	FS_Stream(const std::string& begin, unsigned char* key) {
		uuid_parse(begin.data(),start);
		//Deterministic sector generation
		//Take the base sector GUID, and XOR with sector offset ID
		sector_size = 1024*4;
		EVP_CIPHER_CTX_init(&enc);
		EVP_CIPHER_CTX_init(&dec);
		EVP_EncryptInit_ex(&enc,EVP_aes_256_ecb(),0,key,0);
		EVP_EncryptInit_ex(&dec,EVP_aes_256_ecb(),0,key,0);

	}
	~FS_Stream() {
		EVP_CIPHER_CTX_cleanup(&enc);
		EVP_CIPHER_CTX_cleanup(&dec);
	}

};

class FS_Node {
public:
	char name[256];
	unsigned char sector[16];
	bool operator<(const FS_Node& other) const {
		return strcmp(name,other.name) < 0;
	}
	bool operator==(const FS_Node& other) const {
		return strcmp(name,other.name) == 0;
	}
};
class FS_Dir {
public:
	FS_Stream* str;
	FS_Dir(FS_Stream* stream) {
		str = stream;
	}
	template<typename F>
	void GetNode(uint64_t index, const F& callback) {
		str->Read(index*sizeof(FS_Node),sizeof(FS_Node),[=](unsigned char* mander){
			FS_Node retval;
			memcpy(&retval,mander,sizeof(retval));
			callback(retval);
		});
	}
	template<typename F>
	void Enumerate(const F& callback) {
		//TODO: Finland
	}
	~FS_Dir() {
		delete str;
	}

};




//FS END
static FS_Stream* dev;

char* path;
static int oath_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, "bdev", NULL, 0);

	return 0;
}


static int getaddr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, "/bdev") == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = -1;
	} else
		res = -ENOENT;

	return res;
}

static int oauth_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, "/bdev") != 0)
		return -ENOENT;

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int oauth_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	size_t len;
	(void) fi;
	if(strcmp(path, "/bdev") != 0)
		return -ENOENT;

	Event evt;
	dev->Read(offset,size,[&](unsigned char* mander){
		memcpy(buf,mander,size);
		evt.signal();
	});
	evt.wait();
	return size;
}
static int oauth_write(const char *path, const char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	size_t len;
	(void) fi;
	if(strcmp(path, "/bdev") != 0)
		return -ENOENT;

	dev->Write(offset,size,(unsigned char*)buf);

	return size;
}

void fs_drv(const char* objname, unsigned char* encKey) {
dev = new FS_Stream(objname,encKey);
	char* args[3];
args[0] = path;
args[1] = "-s";
args[2] = "mntpnt";
struct fuse_operations operations;
memset(&operations,0,sizeof(operations));
operations.getattr = getaddr;
operations.readdir = oath_readdir;
operations.open = oauth_open;
operations.read = oauth_read;
operations.write = oauth_write;
}


int main(int argc, char** argv) {
path = argv[0];
    GlobalGrid::P2PConnectionManager mngr;
GlobalGrid::InternetProtocol ip(5809,&mngr);
mngr.RegisterProtocol(&ip);
GGDNS_Init(mngr.nativePtr);
if(argc == 2) {
	//Grace period to allow for network to wake up
	sleep(2);
	//Read GUID from argv[1]
	std::string root = argv[1];
	//Read encryption key
	unsigned char enc_key[32];
	read(STDIN_FILENO,enc_key,32);
	fs_drv(root.data(),enc_key);
	memset(enc_key,0,32);
	return 0;
}
if(mngr.nativePtr == 0) {
    printf("NOTE: Simulated GlobalGrid environment detected -- database changes will only be visible on local network. For access to global database, please purchase a GlobalGrid license.\n");
}




//Script it. Automated tests for GlobalGrid GGDNS integration
printf("Scanning for private key....\n");
std::string thumbprint;
bool(*enumCallback)(void*, const char*);
void* thisptr = C([&](const char* name){
    thumbprint = name;
    return false;
},enumCallback);
GGDNS_EnumPrivateKeys(thisptr,enumCallback);
printf("Ready for commands");
char buffer[1024*4];
auto readline = [&](){
	//read(STDIN_FILENO,buffer,256);
	std::cin.getline(buffer,1024*4);
	return std::string(buffer);
};
std::function<void()> menu = [&]() {
	printf("\n\n0. Run GGDNS query\n1. Add GGDNS object\n2. Add GGDNS domain\n3. Query for DNS locator\n4. List authoritative servers for domain\n5. Mount filesystem\nPlease enter a selection: ");
	std::string input = readline();
	switch(input[0]) {
	case '0':
	{

		printf("Enter object ID: \n");
		std::mutex m;
		std::condition_variable evt;
		std::unique_lock<std::mutex> l(m);
        void(*callback)(void*,NamedObject*);
		bool c = false;
		void* thisptr = C([&](NamedObject* obj){
			if(obj) {
				printf("%s\n",(char*)obj->blob);
			}else {
				printf("Object not found (NOTE: GGDNS entries are case-sensitive)\n");
			}
			c = true;
		},callback);
		std::string id = readline();
		GGDNS_RunQuery(id.data(),thisptr,callback);
		while(!c) {
			sleep(1);
		}
		printf("Operation complete\n");
		menu();
	}
		break;
	case '1':
	{
		printf("Enter GGDNS identifier\n");
		std::string id = readline();
		printf("Enter GGDNS value (up to 4KB)\n ");
		std::string val = readline();
		NamedObject obj;
		obj.authority = (char*)thumbprint.data();
		obj.blob = (unsigned char*)val.data();
		obj.bloblen = val.size();
		GGDNS_MakeObject(id.data(),&obj,0,0);
		printf("Object created successfully.\n");
		menu();
	}
		break;
	case '2':
	{
		printf("Enter parent authoritative domain: ");
		std::string parent = readline();
		printf("Enter name of domain: ");
		std::string dname = readline();
		GGDNS_MakeDomain(dname.data(),parent.data(),thumbprint.data());
		printf("Domain created successfully\n");
	}
		break;
	case '3':
	{
		printf("Enter parent authoritative domain:");
		std::string parent = readline();
		printf("Enter name of domain: ");
		std::string dname = readline();
		void(*cb)(void*,const char*);
		thisptr = C([=](const char* val){
			printf("%s\n",val);
		},cb);
		GGDNS_QueryDomain(dname.data(),parent.data(),thisptr,cb);
	}
		break;
	case '4':
	{
		printf("Enter object ID: ");
		std::string id = readline();
		auto bot = [=](GlobalGrid_Identifier* list, size_t count){
			if(list) {


			for(size_t i = 0;i<count;i++) {
				char mander[256];
				uuid_unparse((unsigned char*)list[i].value,mander);
				printf("%s\n",mander);
			}
			}else {
				printf("Error: Pikachu!\n");
			}
		};
		void(*cb)(void*,GlobalGrid_Identifier*,size_t);
		thisptr = C(bot,cb);
		GGDNS_GetGuidListForObject(id.data(),thisptr,cb);

	}
		break;
	case '5':
	{
		//Mount filesystem
		printf("===================================\nFS MOUNT INSTRUCTIONS\n===================================\nTo mount the filesystem; please specify the filesystem GUID at the command line, and pipe the encryption key to stdin.\n\n\n\n");
		abort();
	}
		break;
	}
};
menu();
sleep(-1);
}
