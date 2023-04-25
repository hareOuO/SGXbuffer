#ifndef DS_MGR_H
#define DS_MGR_H

#include "mbuf_header.h"


const int PAGE_SIZE = 4 * 1024;
const int NUM_PAGE_TOTAL = 50001;

const int CONTENT_ITEM_SIZE = 4;
const int CONTENT_MAX_SIZE = (PAGE_SIZE / CONTENT_ITEM_SIZE);
const int PAGE_NUM_IN_CONTENT = (CONTENT_MAX_SIZE - 1);


struct stest{
private:
    int a;
    int a1()
    {
        a=1;
        return a;
    }
public: 
    stest()
    {
        a=0;
    }
    ~stest()
    {}
    int geta()
    {
        return this->a;
    }
};



struct DataStorageMgr {
private:
    FILE *currFile;
    int numPages;
    long long io_cnt_total;

    int cur_content_id;
    off_t cur_content_offset;
    off_t contents[CONTENT_MAX_SIZE];

    string filename = "data.dbf";
    string filepath = "File/";

    void OpenFile(string filename, bool write) {
        if (write)
            currFile = fopen((filepath + filename).c_str(), "wb+");
        else
            currFile = fopen((filepath + filename).c_str(), "rb+");
    }
    void CloseFile() {
        fclose(currFile);
    }
    void Seek(off_t offset) {//文件指针调整到开头+偏移处
        int ret = fseek(currFile, offset, SEEK_SET);
    }
    // 增加一次IO
    void IncIOCnt() {
        io_cnt_total += 1;
    }
    // fread 的包装函数，会将 [io_cnt_total] 的值 加 1
    void FRead(void *dst, size_t sz, size_t cnt, FILE *fp) {
        int ret = fread(dst, sz, cnt, fp);//从fp中读cnt个sz字节大小的元素到dst中

        IncIOCnt();
    }
    // fwrite 的包装函数，会将 [io_cnt_total] 的值 加 1
    void FWrite(void *str, size_t sz, size_t cnt, FILE *fp) {
        int ret = fwrite(str, sz, cnt, fp);//str写入fp中

        IncIOCnt();
    }
    // 清空目录，重置目录信息
    void ClearContents() {
        memset(contents, 0, sizeof(contents));
        cur_content_id = -1;
        cur_content_offset = 0;
    }
    // 读取目录，seek到offset并读取一个目录到 contents[] 中，第一个目录的 offset=0
    // index: 当前目录在目录链表中的序号
    void ReadContent(off_t offset, int index) {
        Seek(offset);
        ClearContents();
        FRead(contents, 1, sizeof(contents), currFile);
        cur_content_id = index;
        cur_content_offset = offset;
    }
    // 更新目录, seek到offset并将目录写入磁盘
    void WriteContent(off_t offset, int index) {
        Seek(offset);
        FWrite(contents, 1, sizeof(contents), currFile);
        cur_content_id = index;
        cur_content_offset = offset;
    }
    // 跳过[num_skip]个目录节点，最终[contents]中是第 [num_skip] 个目录，返回最终目录的offset
    off_t SkipContent(int num_skip) {
        // 可以直接利用当前已经读取的
        if (cur_content_id == num_skip) {
            return cur_content_offset;
        }
        off_t cont_off = 0;
        int i = 0;
        // 利用已存的目录信息
        if (cur_content_id != -1 && cur_content_id < num_skip) {
            cont_off = contents[CONTENT_MAX_SIZE - 1];
            i = cur_content_id + 1;
        }
        for (; i <= num_skip; i++) {
            ReadContent(cont_off, i);
            if (i == num_skip)
                return cont_off;
            cont_off = contents[CONTENT_MAX_SIZE - 1];
        }
        return cont_off;
    }
    // n pages += 1
    void IncNumpage() {
        numPages += 1;
    }

public:
    DataStorageMgr(bool create_file = true) {
        currFile = nullptr;
        numPages = 0;
        io_cnt_total = 0;
        ClearContents();
        OpenFile(filename, create_file);
    }
    ~DataStorageMgr() {
        //CloseFile();   
    }
    // 读取某个页
    int ReadPage(int page_id, char* buffer) {
        int num_skip = page_id / PAGE_NUM_IN_CONTENT;
        SkipContent(num_skip);
        off_t target_offset = contents[page_id % PAGE_NUM_IN_CONTENT];
        Seek(target_offset);
        FRead(buffer, 1, MBUFFER_SIZE, currFile);
        return 0;
    }
    // 更新某个页，页page_id一定存在，对于新加入的页，调用 [WriteNewPage]
    int WritePage(int page_id, char* buffer) {
        int num_skip = page_id / PAGE_NUM_IN_CONTENT;
        SkipContent(num_skip);
        off_t target_offset = contents[page_id % PAGE_NUM_IN_CONTENT];
        Seek(target_offset);
        FWrite(buffer, 1, MBUFFER_SIZE, currFile);
        return 0;
    }
    // 写入一个新页
    int WriteNewPage(char* buffer) {
        if (numPages == 0) {
            ClearContents();
            const off_t target_offset = sizeof(contents);
            contents[0] = target_offset;
            WriteContent(0, 0);
            Seek(target_offset);
            FWrite(buffer, 1, MBUFFER_SIZE, currFile);
            IncNumpage();
            return 0;
        }
        const int page_id = numPages;
        int num_skip = page_id / PAGE_NUM_IN_CONTENT;
        int target_index = page_id % PAGE_NUM_IN_CONTENT;
        // 需要新建目录
        if (target_index == 0) {
            num_skip -= 1;
            off_t cont_offset = SkipContent(num_skip);
            off_t new_content_offset = contents[PAGE_NUM_IN_CONTENT - 1] + PAGE_SIZE;
            // 更新最后一个目录的 next
            contents[CONTENT_MAX_SIZE - 1] = new_content_offset;
            WriteContent(cont_offset, num_skip);
            // 建立新目录，更新内容并写到磁盘
            ClearContents();
            off_t new_page_offset = new_content_offset + sizeof(contents);
            contents[0] = new_page_offset;
            WriteContent(new_content_offset, num_skip + 1);
            Seek(new_page_offset);
            FWrite(buffer, 1, MBUFFER_SIZE, currFile);
        } else {
            off_t cont_offset = SkipContent(num_skip);
            off_t target_offset = contents[target_index - 1] + PAGE_SIZE;
            contents[target_index] = target_offset;
            WriteContent(cont_offset, num_skip);
            Seek(target_offset);
            FWrite(buffer, 1, MBUFFER_SIZE, currFile);
        }
        IncNumpage();
        return 0;
    }
    int GetNumPages() {
        return numPages;
    }
    int GetTotalIO() {
        return io_cnt_total;
    }
    // ftell
    long Ftell() {
        long ret = ftell(currFile);
        return ret;
    }

};

#endif // DS_MGR_H
