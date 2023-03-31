/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

//#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include "baddtree.h"


#include "Ocall_wrappers.h"
//#include <openssl/aes.h>

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <map>
#include <vector>

using namespace BAT;

BAddTree<int,k_r>* tree;

int test()
{
    char sourceStringTemp[1024];
    char dstStringTemp[1024];
    memset((char*)sourceStringTemp, 0 ,1024);
    memset((char*)dstStringTemp, 0 ,1024);
    //memcpy(sourceStringTemp, tree->m_root,1024);

    BAddTreeLeafNode<int, k_r>* s = (BAddTreeLeafNode<int, k_r>*) sourceStringTemp;
    printf("1root nodeid: %d\n",s->node_id);

    int sour_len = strlen((char*)sourceStringTemp);
    printf("len: %d\n",sour_len);
    if(!aes_encrypt(sourceStringTemp,key,dstStringTemp,1024))
    {
        printf("encrypt error\n");
        return -1;
    }
    printf("enc %d:",strlen((char*)dstStringTemp));
    for(int i= 0;dstStringTemp[i];i+=1){
        printf("%x",(unsigned char)dstStringTemp[i]);
    }
    memset((char*)sourceStringTemp, 0 ,1024);
    if(!aes_decrypt(dstStringTemp,key,sourceStringTemp,1024))
    {
        printf("decrypt error\n");
        return -1;
    }
    printf("\n");
    printf("dec %d:",strlen((char*)sourceStringTemp));
    //printf("%s\n",sourceStringTemp);
    for(int i= 0;i < sour_len;i+=1){
        printf("%x",(unsigned char)sourceStringTemp[i]);
    }
    printf("\n");
    BAddTreeLeafNode<int, k_r>* node = (BAddTreeLeafNode<int, k_r>*) sourceStringTemp;
    return 0;
}

void ecall_init(int order)
{
    printf("ecall_init\n");
    for(int i=1;i<=EBUFFER_SIZE;i++)
    {
        MBuf_id mbuf_id;
        mbuf_id.page_id = (i-1)/4 + 1;
        mbuf_id.offset = (i-1)%4;
        node2page[i] = mbuf_id;
    }
    //自由设置密钥
    for(int i = 0; i < 16; i++)
    {
        key[i] = 32 + i;
    }

    tree = new BAddTree<int,k_r>(order);

    printf("初始化完毕！\n");
}

int ecall_search(int key,void* mbdes,char** mbpool)
{
    //printf("ecall_search\n");
    return 99999;
    return tree->find(key,(MBuf_des*)mbdes,mbpool)->rid;
    
}

void ecall_insert(void* key_rid,void* mbdes,char** mbpool)
{
    printf("ecall_insert\n");
    k_r* kr = (k_r*)key_rid;
    printf("插入key,rid:%d,%d\n",kr->k,kr->rid);
    tree->insert(*kr,(MBuf_des*)mbdes,mbpool);
    
}

auto itf = [&](deque <k_r*>&e) {
	int _s = e.size();
	for (int i = 0; i < _s; ++i) {
		printf("%d ", e[i]->k);
	}
};

void ecall_traversal()
{
    printf("ebuffer size: %d\n",tree->ebuffer->size);
    printf("tree size: %d\n",tree->size());
    printf("start traversal:\n");
    tree->list_traversal(itf);
}
