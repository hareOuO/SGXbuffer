#ifndef EHEADER_H
#define EHEADER_H

//#include "logger.h"
//#include "BAddTreeNode.h"
//#include "baddtree.h"

#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unordered_map>
#include <map>
#include <vector>
#include <iostream>
#include <queue>


const int EBUFFER_SIZE = 1024;
const int EBUFFER_NUM_MAX_SIZE = 8;//最多1024个ebuffer


struct EBuf_pool {
    char field[EBUFFER_SIZE] = {};//buffer pool存储的数据

    int size = EBUFFER_SIZE;

    // 将 src 中的内容复制到 field 中
    void set_field(EBuf_pool &src_buffer) {
        memcpy(field, src_buffer.field, size);
    }
};

struct EBuf_des {
    int node_id;
    int buffer_id;
    int count;
    bool dirty;
    int next_buffer_id, prev_buffer_id;

    EBuf_des() { node_id = buffer_id = next_buffer_id = prev_buffer_id = 1, count = 0, dirty = false; }
    void update(int nid, int bid, int cnt, bool dirty) {
        node_id = nid, buffer_id = bid, count = cnt, this->dirty = dirty;
    }
};

#endif // EHEADER_H
