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
	"net/url"
	"net/http"
)

var (
	warn_count         = 2
	ip_pool            []string
	warn_count_map     = map[string]int{}
	ip_list            = "ip.txt"
	result_ssh         = "result_weak_ssh.txt"
	result_host_passwd = "result_host_passwd.txt"
	password_list      = []string{"123456","root","admin"}
	banner_issue, _    = ioutil.ReadFile("issue.txt")
	sshd_config, _     = ioutil.ReadFile("sshd_config.txt")
	scan_data          = time.Now().Format("2006-01-02")
	motd_banner        = `"\n###【安全警告】###` + scan_data + `\n#该服务器SSH密码过于简单可参考 http://xx.xx.com/pages/1#并请立即修改密码或联系xxxx#\n"`
	chek_warn_add_key  = "echo 'ssh-rsa xxxxxxxxxxx公有keyxxxxxxxxx by sec'>> /root/.ssh/authorized_keys"
)

const username = "root"
const password_salt = "需要自己设置新密码的盐"

type Scan_ssh struct {
	ip             string
	key            string
	salt           string
	password       string
	passwd_session *ssh.Session
	auth_session   *ssh.Session
	weak_pass_vul  bool
	password_vul   bool
	warn_map       string
	sync_data      string
}

func init() {
	buf, _ := ioutil.ReadFile(result_ssh)
	json.Unmarshal(buf, &warn_count_map)
	fmt.Println("last_count_map", warn_count_map)
}

func (self *Scan_ssh) Create_ip_list() []string {
	fi, err := os.Open(ip_list)
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
	addrPort := self.ip + "	:22"
	config := &ssh.ClientConfig{
		Timeout: 5 * time.Second,
		User:    username,
		Auth:    []ssh.AuthMethod{ssh.Password(self.password),},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", addrPort, config)

	if err != nil {
		fmt.Println(self.ip, self.password, "Dail_error")
		self.weak_pass_vul = false
		return
	}
	session, err := client.NewSession()

	if err != nil {
		fmt.Println(self.ip, "Connect_error")
		self.weak_pass_vul = false
		return
	}
	self.passwd_session = session
	self.weak_pass_vul = true

}

func (self *Scan_ssh) marshal_check_warn() {
	warn_count_map[self.ip] = warn_count_map[self.ip] + 1
	buf, _ := json.Marshal(warn_count_map)
	self.warn_map = string(buf)
}

func (self *Scan_ssh) double_verify_auth_key() {
	key, err := ioutil.ReadFile("id_rsa_private_key.txt")

	if err != nil {
		log.Fatalf(self.ip, "unable to read private key: %v", err)
		return
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
			err := self.passwd_session.Run("echo -e " + motd_banner + " > /etc/motd")
			if err != nil {
				fmt.Println("追加Banner失败1", self.ip, err)
				return
			}
			self.passwd_scan_ssh(self.ip)
			motd_res, err := self.passwd_session.Output("cat /etc/motd")
			if err != nil {
				fmt.Println("追加Banner失败2", self.ip, err)
				return
			}
			check_motd := strings.Contains(string(motd_res), "安全警告")
			if (check_motd) {
				fmt.Println(self.ip, "Add_Motd_Successful")
				return
			}
			fmt.Println("追加Banner失败3", self.ip)
		}
	case "add_key":
		{
			self.passwd_scan_ssh(self.ip)
			_, err := self.passwd_session.Output(chek_warn_add_key)
			if err != nil {
				fmt.Println(self.ip, "追加ssh_auth_key失败1")
				return
			}
			self.passwd_scan_ssh(self.ip)
			get_authkey, err := self.passwd_session.Output("cat /root/.ssh/authorized_keys")
			if err != nil {
				fmt.Println("追加ssh_auth_key失败2", self.ip, err)
				return
			}
			check_authkey := strings.Contains(string(get_authkey), "by sec")
			if (check_authkey) {
				fmt.Println(self.ip, "Add_Key_Successful")
				return
			}
			fmt.Println("追加ssh_auth_key失败3", self.ip)
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
				fmt.Println(self.ip, "Banner_issue Fail")
				return
			}
		}
	case "mv_config":
		{
			self.double_verify_auth_key()
			res, _ := self.auth_session.Output("ls /etc/ssh/sshd_config.sec.bak && ls /etc/issue.net.sec.bak && cat /etc/ssh/sshd_config | grep sec && cat /etc/issue.net | grep '安全警告'")
			check_config := strings.Contains(string(res), "安全警告") && strings.Contains(string(res), "2018 by sec") && strings.Contains(string(res), "sshd_config.sec.bak") && strings.Contains(string(res), "/etc/issue.net.sec.bak")
			if check_config {
				fmt.Println(self.ip, "Cmdmv_Already_Successful")
				return
			}

			self.double_verify_auth_key()
			cmd_mv := "mv /etc/ssh/sshd_config /etc/ssh/sshd_config.sec.bak  &&  mv /tmp/sshd_config /etc/ssh/sshd_config && mv /etc/issue.net /etc/issue.net.sec.bak && mv /tmp/issue.net /etc/issue.net"
			err := self.auth_session.Run(cmd_mv)
			if err != nil {
				fmt.Println(self.ip, "执行cmd_mv失败1")
				return
			}
			self.double_verify_auth_key()
			verf_config, err := self.auth_session.Output("ls /etc/ssh/sshd_config.sec.bak && ls /etc/issue.net.sec.bak")
			if err != nil {
				fmt.Println(self.ip, "执行cmd_mv失败2")
				return
			}
			check_config_count := strings.Count(string(verf_config), ".bak")

			if check_config_count == 2 {
				fmt.Println(self.ip, "Bash_command_Successful")
				return
			}
			fmt.Println(self.ip, "执行cmd_mv失败3")
		}

	case "modify_passwd":
		{
			self.double_verify_auth_key()
			cmd_modify_passwd := "echo root:" + self.md5_new_pass() + "|chpasswd && /etc/init.d/sshd restart"
			res, err := self.auth_session.Output(cmd_modify_passwd)
			fmt.Println(self.ip, "Complete The Mission ", string(res))
			if err != nil {
				fmt.Print(self.ip, "执行cmd_modify_passwd失败", err)
				return
			}
		}
	}
}

func (self *Scan_ssh) Write2File(text string) (int, error) {
	f, err := os.OpenFile(result_ssh, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.WriteString(text)
}

func (self *Scan_ssh) Write2File_HostPasswd(text string) (int, error) {
	f, err := os.OpenFile(result_host_passwd, os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0666)
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
	fmt.Printf("%s,NewPasswod:%s \n", self.ip, new_password)
	self.Write2File_HostPasswd(self.ip + "  " + new_password + "\n")
	return new_password
}

//func getCurrentDirectory() string {
//	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
//	if err != nil {
//		log.Fatal(err)
//	}
//	return strings.Replace(dir, "\\", "/", -1)
//}

func (self *Scan_ssh) while_password() {
	for i := 0; i < len(password_list); i++ {
		if self.weak_pass_vul != true {
			self.password = password_list[i]
			self.passwd_scan_ssh(self.ip)
		}
	}
}

func Md5Str(str string) string {
	strMd5 := md5.New()
	strMd5.Write([]byte(str))
	return hex.EncodeToString(strMd5.Sum(nil))
}

func (self *Scan_ssh) sync_ip() {
	t := time.Now()
	for k, v := range warn_count_map {
		if v < warn_count {
			continue
		}
		self.sync_data += k + ","
	}
	timestamp := fmt.Sprintf("%d", t.Unix())
	data := make(url.Values)
	data["t"] = []string{string(t.Unix())}
	data["ip_data"] = []string{self.sync_data}
	data["t"] = []string{timestamp}
	sign := Md5Str("传输IP与后台协商的sign" + timestamp)
	data["sign"] = []string{sign}
	//把post表单发送给目标服务器
	//fmt.Println(data)
	res, err := http.PostForm("http://后台地址接收结果.xx.com/ssh/unlock/add", data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer res.Body.Close()
	fmt.Println(data, "send data Successful")
}

func main() {
	x := &Scan_ssh{}
	x.Create_ip_list()
	pool_len := len(ip_pool)
	start := time.Now().Unix()
	for i := 0; i < pool_len; i++ {
		x := Scan_ssh{ip: strings.TrimSpace(ip_pool[i])}
		x.while_password()
		if x.weak_pass_vul {
			fmt.Println(x.ip, "Dial_Successful")
			x.marshal_check_warn()
			if x.check_warn_add_key() {
				x.double_verify_auth_key()
				fmt.Println(x.ip, "Double_Verify_Authkey Successful")
				x.use_authsession_modify_password()
				x.auth_session.Close()
			}
			x.Write2File(x.warn_map)
			x.passwd_session.Close()
		}
		//fmt.Println("x.warn_map",x.warn_map)
	}
	x.sync_ip()
	fmt.Println(x.sync_data)
	fmt.Printf("Cost time %d 's, Total %d ", time.Now().Unix()-start, len(ip_pool))

}
