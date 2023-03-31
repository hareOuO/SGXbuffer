#if !defined(BUFFER_MGR_H)
#define BUFFER_MGR_H

#include "mbuf_header.h"
#include "ebuf_header.h"
#include "BAddTreeNode.h"

#include "Enclave_t.h"
//#include "Enclave.h"
#include "Ocall_wrappers.h"

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


using namespace BATN;

map<int,MBuf_id> node2page;//ebuffer到mbuffer的地址转换表

char key[AES_BLOCK_SIZE];

struct MBuffer {
//private:
public:
    unordered_map<int, int> page2buffer;
    int buffer2page[MBUFFER_NUM_MAX_SIZE];

    int head_bid, tail_bid, size;

    // 读/写页的操作数
    int tot_page_update_num;
    // 缓存命中次数
    int hit_num;

    // 选择一个受害者
    int SelectVictim() {
        return tail_bid;
    }
    void SetDirty(int buffer_id,MBuf_des* mbdes) {
        mbdes[buffer_id].dirty = true;
    }
    // 将一个dirty的mbuffer写回磁盘
    void WriteBuffer(int buffer_id,char** mbpool) {
        ocall_writepage(buffer2page[buffer_id], mbpool[buffer_id]);
    }
    // 从磁盘读一个page到mbuffer
    void ReadPage(int page_id, char* thebuffer) {
        ocall_readpage(page_id, thebuffer);
    }
    // LRU -- 更新了一个缓冲块（可能淘汰了旧的）
    //对于新插入的缓冲块，使用 [LRUInsert]
    void LRUUpdate(int readed_bid,MBuf_des* mbdes) {
        if (tail_bid == readed_bid) { // 选了尾巴
            // 从尾巴处删除
            tail_bid = mbdes[readed_bid].prev_buffer_id;
            mbdes[tail_bid].next_buffer_id = tail_bid;
        } else { // 更新了中间某个缓冲块
            int prev = mbdes[readed_bid].prev_buffer_id;
            int next = mbdes[readed_bid].next_buffer_id;
            // 删除它
            mbdes[prev].next_buffer_id = next;
            mbdes[next].prev_buffer_id = prev;
        }
        // 加到首部
        mbdes[head_bid].prev_buffer_id = readed_bid;
        mbdes[readed_bid].next_buffer_id = head_bid;
        mbdes[readed_bid].prev_buffer_id = readed_bid;
        head_bid = readed_bid;
    }
    // LRU -- 插入了一个新缓冲块
    void LRUInsert(int inserted_bid,MBuf_des* mbdes) {
        if (size == 0) { // LRU 链表为空
            head_bid = tail_bid = inserted_bid;
            mbdes[head_bid].next_buffer_id = mbdes[head_bid].prev_buffer_id = inserted_bid;
        } else { // 链表不为空
            mbdes[head_bid].prev_buffer_id = inserted_bid;
            mbdes[inserted_bid].next_buffer_id = head_bid;
            mbdes[inserted_bid].prev_buffer_id = inserted_bid;
            head_bid = inserted_bid;
        }
    }
    // 命中缓存，加一
    void IncHitNum() {
        hit_num += 1;
    }
    // 执行了依次读/写页
    void IncTotPageUpdateNum() {
        tot_page_update_num += 1;
    }

public:
    //MBuffer(){}
    MBuffer() {
        memset(buffer2page, -1, sizeof(buffer2page));

        head_bid = tail_bid = -1;
        size = 0;
        hit_num = tot_page_update_num = 0;
    }


    // 读取page_id的内容到ebufferpool
    int FixPage(int node_id, EBuf_pool &thebuffer,MBuf_des* mbdes,char** mbpool) {
        MBuf_id mbuf_id;
        mbuf_id = node2page[node_id];
        int page_id = mbuf_id.page_id;
        int offset = mbuf_id.offset;

        printf("找的pageid,offset: %d %d\n",page_id,offset);

        char dstStringTemp[1024];
        memset((char*)dstStringTemp, 0 ,1024);

        IncTotPageUpdateNum();
        if (page2buffer.find(page_id) != page2buffer.end()) { // 在缓冲区
            printf("MBuffer HIT!\n");
            IncHitNum();
            int mbid = page2buffer[page_id];
            printf("mbdes.page_id: %d\n",mbdes[mbid].page_id);

            memcpy(dstStringTemp, mbpool[mbid]+offset*1024, 1024);
            if(!aes_decrypt(dstStringTemp,key,thebuffer.field,1024))
            {
                printf("decrypt error\n");
            }
            return 0;
        }
        
        // 不在缓冲区
        int target_bid = size;
        bool do_insert = false; // 确定执行更新还是插入操作

        if (size >= MBUFFER_NUM_MAX_SIZE) { // 缓冲区满
            target_bid = SelectVictim();
            if (mbdes[target_bid].dirty == 1) { // dirty
                WriteBuffer(target_bid,mbpool);
            }
        } else { // 缓冲区未满
            target_bid = size;
            do_insert = true;
        }

        // 读数据
        ReadPage(page_id, mbpool[target_bid]);

        mbdes[target_bid].update(page_id, target_bid, 0, false);
        do_insert ? LRUInsert(target_bid,mbdes) : LRUUpdate(target_bid,mbdes);
        do_insert ? size += 1 : 0;

        memcpy(dstStringTemp, mbpool[target_bid]+offset*1024, 1024);
        if(!aes_decrypt(dstStringTemp,key,thebuffer.field,1024))
        {
            printf("decrypt error\n");
        }

        // 更新哈希表
        page2buffer[page_id] = target_bid;
        buffer2page[target_bid] = page_id;
        return 0;
    }

    // 更新某个page
    void UpdatePage(int node_id, EBuf_pool &thebuffer,MBuf_des* mbdes,char** mbpool) {
        
        MBuf_id mbuf_id;
        mbuf_id = node2page[node_id];
        int page_id = mbuf_id.page_id;
        int offset = mbuf_id.offset;

        char dstStringTemp[1024];
        memset((char*)dstStringTemp, 0 ,1024);
        if(!aes_encrypt(thebuffer.field,key,dstStringTemp,1024))
        {
            printf("encrypt error\n");
        }

        /*printf("enc %d:",strlen((char*)dstStringTemp));
        for(int i= 0;dstStringTemp[i];i+=1){
            printf("%x",(unsigned char)dstStringTemp[i]);
        }
        printf("\n");*/

        IncTotPageUpdateNum();
        if (page2buffer.find(page_id) != page2buffer.end()) { // 在缓冲区
            printf("MBuffer HIT!\n");
            IncHitNum();
            int mbid = page2buffer[page_id];
            memcpy(mbpool[mbid]+offset*1024, dstStringTemp, 1024);

            SetDirty(mbid,mbdes);
            LRUUpdate(mbid,mbdes);
            //return;
        } else { // 不在缓冲区
            printf("%d %d %d %s",node_id,page_id,offset,"踢入MBuffer!\n");
            int target_bid = -1, ret = 0;
            bool do_insert = false;
            if (size >= MBUFFER_NUM_MAX_SIZE) { // 缓冲区满
                printf("mbuffer满了\n");
                target_bid = SelectVictim();
                if (mbdes[target_bid].dirty) { // dirty
                    printf("踢入disk\n");
                    ocall_writepage(buffer2page[target_bid], mbpool[target_bid]);

                }
            } else { // 缓冲区未满
                target_bid = size;
                do_insert = true;
            }

            memcpy(mbpool[target_bid]+offset*1024, dstStringTemp, 1024);

            mbdes[target_bid].update(page_id, target_bid, 0, false);
            SetDirty(target_bid,mbdes);
            do_insert ? LRUInsert(target_bid,mbdes) : LRUUpdate(target_bid,mbdes);
            do_insert ? size += 1 : 0;
            // 更新哈希表
            page2buffer[page_id] = target_bid;
            buffer2page[target_bid] = page_id;
        }
    }
    // count减一
    void UnfixPage(int node_id,MBuf_des* mbdes) {

        MBuf_id mbuf_id;
        mbuf_id = node2page[node_id];
        int page_id = mbuf_id.page_id;

        if (page2buffer.find(page_id) != page2buffer.end())
            mbdes[page2buffer[page_id]].count -= 1;
    }
    // 获取命中率
    double GetHitRate() {
        return tot_page_update_num == 0 ? -1 : hit_num / (double)tot_page_update_num;
    }
    // 获取IO总次数
    //long GetIONumTot() {
    //    return ds_mgr->GetTotalIO();
    //}

    // 将所有的 dirty缓冲块写回磁盘
    void WriteDirtys(MBuf_des* mbdes,char** mbpool) {
        for (int bid = 0; bid < size; bid++) {
            if (mbdes[bid].dirty) {
                ocall_writepage(buffer2page[bid], mbpool[bid]);

                mbdes[bid].dirty = false;
            }
        }
    }
};

#endif // BUFFER_MGR_H
