#if !defined(BUFFER_MGR_H)
#define BUFFER_MGR_H

#include "mbuf_header.h"
#include "ebuf_header.h"


struct MBuffer {
//private:
public:
    unordered_map<int, int> page2buffer;
    int buffer2page[MBUFFER_NUM_MAX_SIZE];
    MBuf_des mbuf_des[MBUFFER_NUM_MAX_SIZE];
    MBuf_pool *mbuf_pool;
    int size;


public:
    //MBuffer(){}
    MBuffer(/*DataStorageMgr *ds_mgr*/) {
        memset(buffer2page, -1, sizeof(buffer2page));
        memset(mbuf_des, -1, sizeof(mbuf_des));
        size = 0;
        mbuf_pool = new MBuf_pool[MBUFFER_NUM_MAX_SIZE];
    }
    ~MBuffer() {
        //LOG_DEBUG("~MBuffer");
        delete[] mbuf_pool;
    }

};

#endif // BUFFER_MGR_H
