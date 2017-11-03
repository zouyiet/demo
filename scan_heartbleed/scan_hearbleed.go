package main

import (
	"os"
	"fmt"
	"bufio"
	"io"
	"sync"
	"os/exec"
	"time"
	"bytes"
	"github.com/google/shlex"
	"golang.org/x/net/context"
	"strings"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"crypto/md5"
	"strconv"
)

var (
	maxRoutineNum = 5000
	ch            = make(chan int, maxRoutineNum)
	wg            sync.WaitGroup
	ip_pool       []string
	keys          = " server is vulnerable"
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
	Create_Pool()
}

func Md5(str1 string, str2 string, str3 string) (md5str string) {
	data := []byte(str1 + str2 + str3)
	has := md5.Sum(data)
	md5str = fmt.Sprintf("%x", has)
	return
}

func Timestamp() string {
	t := time.Now()
	string := strconv.FormatInt(t.Unix(), 10)
	return string
}

func Create_Pool() []string {
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

func scan_hearbleed(ip string, ch chan int) {
	defer func(ch chan int) {
		<-ch
		wg.Done()
	}(ch)

	response, _, _ := execTimeout1("python heartbleed.py "+ip, 5)

	if (strings.Contains(response, keys)) {
		r1 := &Result{ip, Md5(ip, "443", Timestamp()), "heartbleed", "443"}
		insertdata := "insert into t_weak_pwd (uniq_flag, ip, port, serv_type)VALUES(?, ?, ?, ?)"
		_, err := db.Exec(insertdata, r1.Md5, r1.Ip, r1.Port, r1.Serv_type)
		fmt.Println(ip," success heartbleed ")
		if err != nil {
			fmt.Println(err)
		}
	}
}

func execTimeout1(command string, timeout int) (string, string, error) {
	p, err := shlex.Split(command)
	if err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
	defer cancel()
	cmd := exec.CommandContext(ctx, p[0], p[1:]...)
	var o, e bytes.Buffer
	cmd.Stdout = &o
	cmd.Stderr = &e
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = ctx.Err()
	}
	return string(o.Bytes()), string(e.Bytes()), err
}

func main() {
	pool_len := len(ip_pool)
	for i := 0; i < pool_len; i++ {
		ch <- 1
		wg.Add(1)
		go scan_hearbleed(ip_pool[i], ch)
	}

	wg.Wait()
	db.Close()

}
