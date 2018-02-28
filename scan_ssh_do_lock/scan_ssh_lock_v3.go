package main

import (
	"golang.org/x/crypto/ssh"
	"net"
	"fmt"
	"time"
	"os"
	"bufio"
	"io"
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"
	"crypto/md5"
	"encoding/hex"
)

var (
	userFile          = "D:/code/go/scan_ssh/scan_ssh_lock/history.txt"
	ip_pool           []string
	warn_count_map    = map[string]int{}
	warn_count        = 10
	banner_issue, _   = ioutil.ReadFile("D:/code/go/scan_ssh/scan_ssh_lock/issue.txt")
	sshd_config, _    = ioutil.ReadFile("D:/code/go/scan_ssh/scan_ssh_lock/sshd_config.txt")
	scan_data         = time.Now().Format("2006-01-02")
	motd_banner       = `"\n###【安全部警告】###` + scan_data + `\n#该服务器SSH密码过于简单可参考xxxx#\n"`
	chek_warn_add_key = "echo 'ssh-rsa xxxxxxxxxx'>> /root/.ssh/authorized_keys"
)

const username = "root"
const password = "daxueba"
const password_salt = "jdsec"

type Scan_ssh struct {
	ip             string
	key            string
	salt           string
	passwd_session *ssh.Session
	auth_session   *ssh.Session
	weak_pass_vul  bool
	warn_map       string
}

func init() {
	buf, _ := ioutil.ReadFile(userFile)
	json.Unmarshal(buf, &warn_count_map)
	fmt.Println("last_count_map", warn_count_map)
}

func (self *Scan_ssh) Create_ip_list() []string {
	fi, err := os.Open("D:/code/go/scan_ssh/scan_ssh_lock/ip.txt")
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

func (self *Scan_ssh) passwd_scan_ssh(ip string) {
	addrPort := self.ip + ":22"
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
		fmt.Println(self.ip, "Dail_error")
		self.weak_pass_vul = false
		return
	}
	session, err := client.NewSession()

	if err != nil {
		fmt.Println(self.ip, "Connect_error")
		self.weak_pass_vul = false
		return
	}
	fmt.Println(self.ip, "Dial_successful")
	self.passwd_session = session
	self.weak_pass_vul = true
}

func (self *Scan_ssh) marshal_check_warn() {
	warn_count_map[self.ip] = warn_count_map[self.ip] + 1
	buf, _ := json.Marshal(warn_count_map)
	self.warn_map = string(buf)
}
func (self *Scan_ssh) double_verify_auth_key() {
	key, err := ioutil.ReadFile("D:/code/go/scan_ssh/scan_ssh_lock/id_rsa_private_key.txt")

	if err != nil {
		log.Fatalf(self.ip, "unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)

	if err != nil {
		log.Fatalf(self.ip, "unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", self.ip+":22", config)

	if err != nil {
		log.Fatalf(self.ip, "double_verf_Dial: %v", err)
		return
	}
	session, err := client.NewSession()

	if err != nil {
		return
	}
	fmt.Println(self.ip, "double_verify_auth_key successful")
	self.auth_session = session
}

func (self *Scan_ssh) check_warn_add_key() bool {
	if (warn_count_map[self.ip] >= warn_count) {
		self.run_command("add_key")
		return true
	} else {
		self.run_command("add_motd")
		return false
	}
}

func (self *Scan_ssh) use_authsession_modify_password() {
	self.run_command("sshd_config")
	self.run_command("add_issue")
	self.run_command("mv_config")
	self.run_command("modify_passwd")
}

func (self *Scan_ssh) run_command(command string) {
	self.passwd_session.Stdout = os.Stdout
	self.passwd_session.Stderr = os.Stderr
	switch command {
	case "add_motd":
		{
			err := self.passwd_session.Run("echo -e " + motd_banner + " >> /etc/motd")
			if err != nil {
				fmt.Println("追加Banner失败", self.ip, err)
				return
			}
			fmt.Println(self.ip, "add_motd successful")
		}
	case "add_key":
		{
			self.passwd_scan_ssh(self.ip)
			_, err := self.passwd_session.Output(chek_warn_add_key)
			if err != nil {
				fmt.Println(self.ip, "add_key fail")
				return
			}
			fmt.Println(self.ip, "add_key successful")
		}
	case "sshd_config":
		{
			self.double_verify_auth_key()
			self.auth_session.Run(string(sshd_config))
		}
	case "add_issue":
		{
			self.double_verify_auth_key()
			err := self.auth_session.Run(string(banner_issue))
			if err != nil {
				fmt.Println(self.ip, "banner_issue fail")
				return
			}
		}
	case "mv_config":
		{
			self.double_verify_auth_key()
			cmd_mv := "mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak  &&  mv /tmp/sshd_config /etc/ssh/sshd_config && mv /etc/issue.net /etc/issue.net.bak && mv /tmp/issue.net /etc/issue.net"
			err := self.auth_session.Run(cmd_mv)
			if err != nil {
				fmt.Println(self.ip, "cmd_mv fail")
				return
			}
		}
	case "modify_passwd":
		{
			self.double_verify_auth_key()
			cmd_modify_passwd := "echo root:" + string(self.md5_new_pass()) + "|chpasswd && /etc/init.d/ssh restart"
			err := self.auth_session.Run(cmd_modify_passwd)
			if err != nil {
				fmt.Println(self.ip, "cmd_modify_passwd fail")
				return
			}
		}
	}
}

func (self *Scan_ssh) Write2File(text string) (int, error) {
	f, err := os.OpenFile(userFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.WriteString(text)
}

func (self *Scan_ssh) md5_new_pass() string {
	new_re_ip := strings.Replace(self.ip, ".", "", -1)
	h := md5.New()
	h.Write([]byte(new_re_ip + password_salt))
	cipherStr := h.Sum(nil)
	new_password := hex.EncodeToString(cipherStr)[:8]
	fmt.Printf("ip:%s,   newpasswd:%s \n", self.ip, new_password)
	return new_password
}

func main() {
	x := &Scan_ssh{}
	x.Create_ip_list()
	pool_len := len(ip_pool)
	start := time.Now().Unix()
	for i := 0; i < pool_len; i++ {
		x := Scan_ssh{ip: ip_pool[i]}
		x.passwd_scan_ssh(x.ip)
		if x.weak_pass_vul {
			x.marshal_check_warn()
			if x.check_warn_add_key() {
				x.double_verify_auth_key()
				x.use_authsession_modify_password()
				x.auth_session.Close()
			}
			x.Write2File(x.warn_map)
			x.passwd_session.Close()
		}
	}
	fmt.Printf("Cost time %d 's, Total %d ", time.Now().Unix()-start, len(ip_pool))
}
