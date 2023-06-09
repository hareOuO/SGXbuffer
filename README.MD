# 存储引擎
模拟存储引擎的缓冲区管理与磁盘数据存储管理接口。

## 功能描述

### 数据管理 ds_mgr
- 上层为缓冲区管理提供数据操作接口
- 下层为操作系统磁盘文件系统
- 外部接口
  - 初始化相关文件信息
  - 读取一个page
  - 写入一个新page
  - 更新一个page
  - 获取页数、IO总数
- 内部接口
  - 读取目录

### 缓冲区管理 buffer_mgr
- 上层为记录查询提供增删改查功能
- 下层调用数据管理接口的功能
- 外部接口
  - 读取某个page内容
  - 更新某个page内容
  - 增加一个新page
  - 获取某个buffer
  - 获取命中率
  - 获取IO总数
  - 获取LRU头、尾信息
  - 将所有脏页写入磁盘
  - 获取可用buffer数目
- 内部接口
  - 根据淘汰算法选择受害者
  - 设置/取消设置一个页为脏页
  - 将所有脏页写入磁盘
  - 打印一个buffer的内容
  - 根据LRU算法更新一个缓冲块
  - 根据LRU算法插入一个新的缓冲块

## 数据结构设计
### ds_mgr 数据结构设计
页大小为4KB，使用一页作为目录，存储`N=(4*1024/4)=1024`个页地址和下一个目录表的地址。其中页地址与目录表地址为偏移量，使用整数(4Byte)表示。

- 文件指针: FILE* fp
- 页数: numpages
- 目录表: contents -> int[]

### buffer_mgr 数据结构设计
- 缓冲区: buffer[]
- 缓冲区大小: size
- 链表首/尾: head_buffer_id, tail_buffer_id
- buffer->page: buffer2page[] 数组
- page->buffer: page2buffer[] 哈希表
- 缓冲块信息(链表节点): Buf_des[] -> { buffer_id, page_id, dirty, count, prev_buffer_id, next_buffer_id }
  - 链表结构与哈希表结合

## 流程设计
### ds_mgr 流程设计
每个目录能够索引x个页
- 读一个页p
  - 跳过`p / x`个目录项
  - 读取目录第`p % x`个项
- 写一个页p
  - 跳过`p / x`个目录项
  - 写入目录第`p % x`个项
- 写一个新页
  - `numpages == 0` 文件为空
    - 建新目录 更新目录
    - 目录写入磁盘
    - 数据写入磁盘
  - `p % x == 0`，需要新建目录
    - 跳过`p / x - 1`个目录，得到文件中的最后一个目录
    - 更新最后一个目录中的下一个目录表的值为最后一个页的`offset + page_size`
    - 当前目录写入磁盘
    - 建立新的目录，其第0页的offset为 最后一个页的`offset + page_size + content_size`
    - 新目录写入磁盘
    - 将新页写到第0页处
  - `p % x != 0`
    - 跳过`p / x`个目录项
    - 新页的偏移量为最后一个页的`offset + page_size`
    - 更新目录，写入磁盘
    - 将新页写入磁盘
  - 增加numpages

### buffer_mgr 流程
- 读page
  - 在缓冲区
    - 获得buffer标识
    - 调用ds_mgr读取数据
    - 返回数据
  - 不在缓冲区
    - 缓冲区满
      - 淘汰一个buffer - LRU
      - buffer是dirty的
        - 调用ds_mgr写回磁盘
    - 缓冲区不满
      - 选择空缓冲块
    - 调用ds_mgr读取page数据到缓冲区
    - LRU更新
    - 返回数据
- 写page
  - 在缓冲区
    - 更新缓冲区数据
    - 设置为dirty
    - LRU更新
  - 不在缓冲区
    - 缓冲区满
      - 淘汰一个buffer - LRU
      - dirty？
        - 调用ds_mgr写回磁盘
    - 缓冲区未满
       - 选择一个空缓冲块
    - 调用ds_mgr读取page数据到缓冲区
    - 更新数据
    - 设置为dirty
    - LRU更新


