package main

import (
	"fmt"
	"os"
	"io"
	"bufio"
	"sync"
	"time"
	"gopkg.in/mgo.v2"
	"crypto/md5"
	_ "database/sql"
	_ "github.com/go-sql-driver/mysql"
	"database/sql"
)

var (
	ip_pool       []string
	pool_len      int
	maxRoutineNum = 10000
	ch            = make(chan int, maxRoutineNum)
	wg            sync.WaitGroup
	today         = time.Now().Format("2006-01-02")
	db            *sql.DB
)

type Result struct {
	Ip        string
	Md5       string
	Serv_type string
	Port      string
}

func init() {
	db, _ = sql.Open("mysql", "root:root@tcp(localhost:3306)/service_weakscan?charset=utf8")
	db.SetMaxOpenConns(2000)
	db.SetMaxIdleConns(1000)
	db.Ping()
}

func Md5(str1 string, str2 string) (md5str string) {
	data := []byte(str1 + str2)
	has := md5.Sum(data)
	md5str = fmt.Sprintf("%x", has)
	return
}

func Ip_pool() []string {
	fi, err := os.Open("private_ip.txt")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return nil
	}
	defer fi.Close()

	br := bufio.NewReader(fi)
	for {
		ip, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		ip_pool = append(ip_pool, string(ip))
	}
	return ip_pool
}

func Scan_Mongodb(ip string, ch chan int) {
	defer func(ch chan int) {
		<-ch
		wg.Done()
	}(ch)

	session, err := mgo.Dial(ip + ":27017")
	if err != nil {
		return
	}
	defer session.Close()
	res, err := session.DatabaseNames()
	if err != nil {
		return
	}
	fmt.Println("success :", ip, res)
	r1 := &Result{ip, Md5(ip, "27017"), "mongodb", "27017"}
	insertdata := "insert into t_weak_pwd (uniq_flag, ip, port, serv_type)VALUES(?, ?, ?, ?)"
	_, err = db.Exec(insertdata, r1.Md5, r1.Ip, r1.Port, r1.Serv_type)
	if err != nil {
		fmt.Println(err)
	}
}

func Read_Mongodb() {
	pool_len = len(ip_pool)
	for i := 0; i < pool_len; i++ {
		ch <- 1
		wg.Add(1)
		go Scan_Mongodb(ip_pool[i], ch)
	}
}

func main() {
	Ip_pool()
	Read_Mongodb()
	wg.Wait()
	db.Close()
}
