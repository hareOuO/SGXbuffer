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


#include <stdio.h>
#include <string.h>
#include <assert.h>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "mysql.h"
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
//#include "mbuffer.h"
#include "ds_mgr.h"

#include <iostream>
//#include <openssl/aes.h>
//#include <openssl/md5.h>
#include <stdlib.h>
#include <math.h>
#include <map>
#include <vector>
#include <fstream>
#include <time.h> 
#include <random>
#include <set>
#include <queue>

using namespace std;
using std::make_pair;
using std::pair;
using std::set;
using std::stoi;
using std::vector;


extern const int NUM_PAGE_TOTAL;
extern const int PAGE_SIZE;
extern const int MBUFFER_SIZE;
//extern bool LOG_DEBUG_ON;



extern "C"
{
    
    /*xxx_init
    这个函数会在自定义的xxx函数调用前被调用, 进行基本的初始化工作, 其完整定义如下:
    my_bool xxx_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    返回值: 1代表出错, 可以在message中给出错误信息并且返回给客户端, 0表示正确执行.信息长度不能大于MYSQL_ERRMSG_SIZE
    函数功能: 该函数的主要功能一般是分配空间, 函数参数检查的等. 如果不需要做任何操作, 直接返回0即可.

    xxx_deinit
    该函数用于释放申请的空间, 其完整定义如下:
    void xxx_deinit(UDF_INIT *initid);
    函数功能: 该函数的功能主要是释放资源, 如果在xxx_init中申请了内存, 可以在此处释放, 该函数在用户函数xxx执行以后执行
    */

    long long test(UDF_INIT *initid, UDF_ARGS *args,  char *is_null, char *err);
    my_bool test_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void test_deinit(UDF_INIT* initid);


    long long pageinit(UDF_INIT *initid, UDF_ARGS *args,  char *is_null, char *err);
    my_bool pageinit_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void pageinit_deinit(UDF_INIT* initid);

    char* getkey(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
    my_bool getkey_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void getkey_deinit(UDF_INIT* initid);

    long long readkey(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err);
    my_bool readkey_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void readkey_deinit(UDF_INIT* initid);

    // long long insert(UDF_INIT *initid, UDF_ARGS *args,  char *is_null, char *err);
    // my_bool insert_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    // void insert_deinit(UDF_INIT* initid);

    long long search(UDF_INIT *initid, UDF_ARGS *args,  char *is_null, char *err);
    my_bool search_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void search_deinit(UDF_INIT* initid);
}




/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;


vector<int> keys;


typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)//0是成功 -1是失败
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}


DataStorageMgr* ds_mgr;

void ocall_writepage(int page_id, char* buffer_field)
{
    ds_mgr->WritePage(page_id,buffer_field);

}

void ocall_readpage(int page_id,char* buffer_field)
{
    ds_mgr->ReadPage(page_id,buffer_field);
}


auto ha = [](const char *str) -> void {
    printf("%s\n", str);
};


// 初始化所有记录到磁盘
bool ds_init() {

    printf("PAGE_SIZE: %d, NUM_DATA = %d\n", PAGE_SIZE, NUM_PAGE_TOTAL);

    ha("Start Writing Data Into Pages");
    DataStorageMgr init_dsmgr = DataStorageMgr(true);
    char tmpbuffer[4096];

    for (int i = 0; i < NUM_PAGE_TOTAL; i++) {
        memset(tmpbuffer, 0, sizeof(tmpbuffer));
        for (int j = 0; j < MBUFFER_SIZE; j++)//MBUFFER_SIZE=4096
            tmpbuffer[j] = 'a' + (j % 26);//使用一个页大小的数据测试
        init_dsmgr.WriteNewPage(tmpbuffer);
    }
    ha("Data Written, Start Job");
    return true;
}


// 执行任务
void m2estart() {

    ds_mgr = new DataStorageMgr(false);
    
    int order = 5;
    ecall_init(global_eid,order);

    ha("Start Reading Command Data");
    // 读取数据到内存
    ha("Command Data Read, Start Processing");
    // 处理读写命令，每次都输出命中率

    MBuf_des mbuf_des[MBUFFER_NUM_MAX_SIZE];
    memset(mbuf_des, -1, sizeof(mbuf_des));
    

    char** mbuf_pool = NULL;
    mbuf_pool = (char**)malloc(sizeof(char*) * (1024));
    for(int i=0;i<1024;i++)
    {
        mbuf_pool[i]=(char*)malloc(4096);
    }

    ifstream de("File/test.in");
    while(!de.eof())
    {
        int cmd=0, key=0, rid=0;
        de >> cmd >> key;
        if(cmd == 0)
        {
            int rid = 0;
            ecall_search(global_eid,&rid,key,mbuf_des,mbuf_pool);
            cout<<"找到了! rid: "<<rid<<endl;
        }
        if (cmd == 1) 
        {
            de >> rid;
            k_r key_rid(key,rid);//key-value对
            ecall_insert(global_eid,&key_rid,mbuf_des,mbuf_pool);
            cout<<"插入完毕！"<<endl;
        }
    }
    de.close();

    //tree.ebuffer->WriteDirtys();
    ecall_traversal(global_eid);

    ha("Processing Over, Job Done!");
}


my_bool test_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    int ret = initialize_enclave();
    if (ret != 0)
    {
        return NULL;
    }
    return 0;
}

long long test(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err)
{
    int a=1;
    cout<<a<<endl;
    int b=*((long long *)args->args[0]);
    return a+b;
}

void test_deinit(UDF_INIT* initid){
    sgx_destroy_enclave(global_eid);
    return;
}







my_bool pageinit_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    int ret = initialize_enclave();
    if (ret != 0)
    {
        return NULL;
    }
    return 0;
}

long long pageinit(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err)
{
    if(ds_init())
    {
        return 1;
    }
}

void pageinit_deinit(UDF_INIT* initid){
    sgx_destroy_enclave(global_eid);
    return;
}



my_bool getkey_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    int ret = initialize_enclave();
    if (ret != 0)
    {
        //ret_error_support(ret);
        return NULL;
    }
    return 0;
}

char* getkey(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error){
    keys.clear();
    ds_mgr = new DataStorageMgr(false);
    
    int order = 5;
    ecall_init(global_eid,order);

    ha("Start Reading Command Data");
    // 读取数据到内存
    ha("Command Data Read, Start Processing");
    // 处理读写命令，每次都输出命中率

    MBuf_des mbuf_des[MBUFFER_NUM_MAX_SIZE];
    memset(mbuf_des, -1, sizeof(mbuf_des));
    

    char** mbuf_pool = NULL;
    mbuf_pool = (char**)malloc(sizeof(char*) * (1024));
    for(int i=0;i<1024;i++)
    {
        mbuf_pool[i]=(char*)malloc(4096);
    }

    ifstream de("File/test.in");
    if(!de){
        char* meg = "Wrong Open";
        strcpy(result,meg);
        *length = strlen(meg);
        return result;
    }

    while(!de.eof())
    {
        int cmd=0, key=0, rid=0;
        de >> cmd >> key;
        if(cmd == 0)
        {
            // int rid = 0;
            // ecall_search(global_eid,&rid,key,mbuf_des,mbuf_pool);
            // cout<<"找到了! rid: "<<rid<<endl;
        }
        if (cmd == 1) 
        {
            de >> rid;
            keys.push_back(key);
            k_r key_rid(key,rid);//key-value对
            ecall_insert(global_eid,&key_rid,mbuf_des,mbuf_pool);
            // cout<<"插入完毕！"<<endl;
        }
    }
    de.close();

    //tree.ebuffer->WriteDirtys();
    ecall_traversal(global_eid);

    char* meg = "Success";
    strcpy(result,meg);
    *length = strlen(meg);
    return result;
}

void getkey_deinit(UDF_INIT* initid){
    sgx_destroy_enclave(global_eid);
    return;
}



my_bool readkey_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    int ret = initialize_enclave();
    if (ret != 0)
    {
        return NULL;
    }
    return 0;
}

long long readkey(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err){
    int i=*((long long *)args->args[0]);
    if(i<keys.size())
    {
        return keys[i];
    }
    else
        return -1;
}

void readkey_deinit(UDF_INIT* initid){
    sgx_destroy_enclave(global_eid);
}


my_bool search_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
    int ret = initialize_enclave();
    if (ret != 0)
    {
        return NULL;
    }
    return 0;
}

long long search(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err)
{
    ds_mgr = new DataStorageMgr(false);
    
    int order = 5;
    ecall_init(global_eid,order);

    MBuf_des mbuf_des[MBUFFER_NUM_MAX_SIZE];
    memset(mbuf_des, -1, sizeof(mbuf_des));
    
    char** mbuf_pool = NULL;
    mbuf_pool = (char**)malloc(sizeof(char*) * (1024));
    for(int i=0;i<1024;i++)
    {
        mbuf_pool[i]=(char*)malloc(4096);
    }
    
    int key=*((long long *)args->args[0]);
    int rid = 0;
    ecall_search(global_eid,&rid,key,mbuf_des,mbuf_pool);
    cout<<"找到了! rid: "<<rid<<endl;
    return rid;
}

void search_deinit(UDF_INIT* initid){
    sgx_destroy_enclave(global_eid);
    return;
}

// my_bool insert_init(UDF_INIT *initid, UDF_ARGS *args, char *message){
//     int ret = initialize_enclave();
//     if (ret != 0)
//     {
//         return NULL;
//     }
//     return 0;
// }

// long long insert(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err){
//     //后面搞清楚des是干什么的
//     MBuf_des mbuf_des[MBUFFER_NUM_MAX_SIZE];
//     memset(mbuf_des, -1, sizeof(mbuf_des));
    

//     char** mbuf_pool = NULL;
//     mbuf_pool = (char**)malloc(sizeof(char*) * (1024));
//     for(int i=0;i<1024;i++)
//     {
//         mbuf_pool[i]=(char*)malloc(4096);
//     }
//     int key = *((long long *)args->args[0]);
//     int rid = *((long long *)args->args[1]);
//     k_r key_rid(key,rid);//key-value对
//     ecall_insert(global_eid,&key_rid,mbuf_des,mbuf_pool);
//     cout<<"插入完毕！"<<endl;
//     return 1; 
// }

// void insert_deinit(UDF_INIT* initid){
//     sgx_destroy_enclave(global_eid);
// }





/* Application entry */

/*int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    // Initialize the enclave 
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    // 写入数据
    ds_init();
    // 执行任务
    m2estart();
    	
    // Destroy the enclave 
    sgx_destroy_enclave(global_eid);
    

    return 0;
}
*/
