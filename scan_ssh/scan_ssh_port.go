package main

import (
	"golang.org/x/crypto/ssh"
	"net"
	"fmt"
	"time"
	"sync"
	"os"
	"bufio"
	"io"
	"strings"
)

var (
	maxRoutineNum = 100
	ch            = make(chan int, maxRoutineNum)
	wg            sync.WaitGroup
	ip_pool       []string
	count         = 0
)

const username = "root"
const password = "1qaz@WSX"

func Create_Pool() []string {
	fi, err := os.Open("D:/code/go/1.txt")
	if err != nil {
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

func scan(ip string, ch chan int) {
	defer func(ch chan int) {
		<-ch
		wg.Done()
	}(ch)

	addrPort := ip + ":22"

	config := &ssh.ClientConfig{
		Timeout: 5 * time.Second,
		User:    username,
		Auth:    []ssh.AuthMethod{ssh.Password(password),},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", addrPort, config)

	if err != nil {
		return
	}
	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	res, err := session.Output("whoami")

	if err != nil {
		return
	}

	check_root := strings.Contains(string(res), "root")

	if (check_root){
		count = count + 1
		fmt.Println(addrPort,count)
	}
}


func main() {
	Create_Pool()
	pool_len := len(ip_pool)
	start := time.Now().Unix()
	for i := 0; i < pool_len; i++ {
		ch <- 1
		if i%1000 == 0 {
			fmt.Println("done:", i)
		}
		wg.Add(1)
		go scan(ip_pool[i], ch)
	}
	wg.Wait()
	fmt.Printf("Cost time %d 's, Total %d , waekpass_count %d ,", time.Now().Unix()-start, len(ip_pool), count)

}
