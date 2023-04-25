CREATE DATABASE IF NOT EXISTS datatest;
drop function pageinit;
drop function getkey;
drop function readkey;
drop function search;
drop function destory;
create function pageinit returns integer soname 'app.so';
create function getkey returns string soname 'app.so';
create function readkey returns integer soname 'app.so';
create function search returns integer soname 'app.so';
create function destory returns integer soname 'app.so';
use datatest;
CREATE TABLE IF NOT EXISTS tt (
    keyword INT PRIMARY KEY,
    rid INT
)ENGINE=INNODB;
--delete from tt where id <= 100000;
select pageinit();
DROP PROCEDURE IF EXISTS test;--如果存在存储过程则删除
DELIMITER $--指定分隔符
CREATE PROCEDURE test()--插入数据
BEGIN
    DECLARE i INT DEFAULT 1;
    DECLARE start_time VARCHAR(128);
    DECLARE end_time VARCHAR(128);
    SET start_time = current_timestamp(6); 
    WHILE i<=1000 DO
        INSERT INTO tt(keyword,rid) VALUES(readkey(i),i);
        SET i = i+1;
    END WHILE;
    SET end_time = current_timestamp(6);
    select start_time;
    select end_time;
END $
DELIMITER  ;
select getkey();
CALL test();
select current_timestamp(6);
select search(10);
select current_timestamp(6);
select current_timestamp(6);
select search(17);
select current_timestamp(6);