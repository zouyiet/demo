package main

import (
	"github.com/go-redis/redis"
	"time"
	"os"
	"bufio"
	"io"
	"strings"
	"sync"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"crypto/md5"
	"database/sql"
)

var (
	pool          []string
	maxRoutineNum = 2000
	ch            = make(chan int, maxRoutineNum)
	wg            sync.WaitGroup
	db 			  *sql.DB
)

type Result struct {
	Ip        string
	Md5       string
	Serv_type string
	Port      string
}

func init(){
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

func NewClient(ip string, ch chan int) () {
	defer func(ch chan int) {
		<-ch
		wg.Done()
	}(ch)
	client := redis.NewClient(&redis.Options{
		Addr:        ip + ":6379",
		Password:    "",
		DB:          0,
		DialTimeout: 3 * time.Second,
	})
	_, err := client.Ping().Result()
	if err != nil {
		return
	}
	Check_root_dir(ip, *client)
}

func Check_root_dir(ip string, client redis.Client) {
	flag := "unauthorized"
	key_1 := "keys"
	r1 := &Result{ip, Md5(ip, "6379"), "redis", "6379"}
	configget, err := client.ConfigGet("dbfilename").Result()

	if err != nil {
		return
	} else {
		if len(configget) > 1 {
			if (strings.Contains(configget[1].(string), key_1)) {
				flag = "Danger_and_unauthorized"
			}
		}
		insertdata := "insert into t_weak_pwd (uniq_flag, ip, port, serv_type, remark)VALUES(?, ?, ?, ?, ?)"
		_, err := db.Exec(insertdata, r1.Md5, r1.Ip, r1.Port, r1.Serv_type, flag)
		fmt.Println(ip,flag)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func Read_Ip_To_Pool() []string {
	file, _ := os.Open("private_ip.txt")
	buf := bufio.NewReader(file)
	for {
		data, _, err := buf.ReadLine()
		if err == io.EOF {
			break
		}
		pool = append(pool, strings.TrimSpace(string(data)))
	}
	return pool
}

func main() {
	Read_Ip_To_Pool()
	for i := 0; i < len(pool); i++ {
		ch <- 1
		wg.Add(1)
		go NewClient(pool[i], ch)
	}
	wg.Wait()
	db.Close()
}
