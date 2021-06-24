package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/go-gomail/gomail"
	"github.com/jumpserver/koko/pkg/config"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jumpserver/koko/pkg/i18n"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/model"
	"github.com/jumpserver/koko/pkg/utils"
)

type EmailParam struct {
	// ServerHost 邮箱服务器地址，如腾讯企业邮箱为smtp.exmail.qq.com
	ServerHost string
	// ServerPort 邮箱服务器端口，如腾讯企业邮箱为465
	ServerPort int
	// FromEmail　发件人邮箱地址
	FromEmail string
	// FromPasswd 发件人邮箱密码（注意，这里是明文形式），TODO：如果设置成密文？
	FromPasswd string
	// Toers 接收者邮件，如有多个，则以英文逗号(“,”)隔开，不能为空
	Toers string
	// CCers 抄送者邮件，如有多个，则以英文逗号(“,”)隔开，可以为空
	CCers string
}

// 全局变量，因为发件人账号、密码，需要在发送时才指定
// 注意，由于是小写，外面的包无法使用
var serverHost, fromEmail, fromPasswd string
var serverPort int

var m *gomail.Message

func InitEmail(ep *EmailParam) {
	toers := []string{}

	serverHost = ep.ServerHost
	serverPort = ep.ServerPort
	fromEmail = ep.FromEmail
	fromPasswd = ep.FromPasswd

	m = gomail.NewMessage()

	if len(ep.Toers) == 0 {
		return
	}

	for _, tmp := range strings.Split(ep.Toers, ",") {
		toers = append(toers, strings.TrimSpace(tmp))
	}

	// 收件人可以有多个，故用此方式
	m.SetHeader("To", toers...)

	//抄送列表
	if len(ep.CCers) != 0 {
		for _, tmp := range strings.Split(ep.CCers, ",") {
			toers = append(toers, strings.TrimSpace(tmp))
		}
		m.SetHeader("Cc", toers...)
	}

	// 发件人
	// 第三个参数为发件人别名，如"李大锤"，可以为空（此时则为邮箱名称）
	m.SetAddressHeader("From", fromEmail, "")
}

// 获取本机IP地址
func externalIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip := getIpFromAddr(addr)
			if ip == nil {
				continue
			}
			return ip, nil
		}
	}
	return nil, errors.New("connected to the network?")
}
func getIpFromAddr(addr net.Addr) net.IP {
	var ip net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	if ip == nil || ip.IsLoopback() {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil // not an ipv4 address
	}

	return ip
}

// SendEmail body支持html格式字符串
func SendEmailProxyServer(command string, proxyServer *ProxyServer) {

	// 获取IP地址
	//ip, getIpErr := externalIP()
	//if getIpErr != nil {
	//	ip.String()
	//	logger.Info("获取本机IP地址时，出现了错误 = %s", getIpErr)
	//}

	hostIp := proxyServer.Asset.Hostname
	Platform := proxyServer.Asset.Platform

	cf := config.GetConf()
	registorHostName := cf.Name

	timeStr := time.Now().Format("2006-01-02 15:04:05")
	subject := "高危命令告警"
	body := "高危指令：" + command + "<br>" +
		"资产IP地址hostIp：" + hostIp + "<br>" +
		"资产系统类型：" + Platform + "<br>" +
		"资产注册名称：" + registorHostName + "<br>" +
		"时间：" + timeStr

	//body :=  "用户在主机[ " + registorHostName + "——" + ip.String() + " ]上执行了高危命令[ " + command + " ]，" + timeStr

	logger.Infof("start ########## 出现高危命令啦 %s，发送邮件给管理员。", body)
	alarmServerHost := cf.AlarmServerHost
	alarmServerPort := cf.AlarmServerPort
	alarmFromEmail := cf.AlarmFromEmail
	alarmFromPasswd := cf.AlarmFromPasswd
	alarmReceiveEmail := cf.AlarmReceiveEmail

	// 结构体赋值
	myEmail := &EmailParam{
		ServerHost: alarmServerHost,
		ServerPort: alarmServerPort,
		FromEmail:  alarmFromEmail,
		// 126邮箱的授权码；
		FromPasswd: alarmFromPasswd,
		Toers:      alarmReceiveEmail,
	}

	defer func() { // 必须要先声明defer，否则不能捕获到panic异常
		InitEmail(myEmail)

		// 主题
		m.SetHeader("Subject", subject)

		// 正文
		m.SetBody("text/html", body)

		d := gomail.NewPlainDialer(serverHost, serverPort, fromEmail, fromPasswd)
		// 发送
		err := d.DialAndSend(m)
		if err != nil {
			logger.Info("发送邮件 \""+body+" \" 失败，因为出现了错误 = %s", err)
		}
	}()

	logger.Infof("end ######### 出现高危命令啦 %s，发送邮件给管理员。", body)
}

// SendEmail body支持html格式字符串
func SendEmail(command string) {

	// 获取IP地址
	ip, getIpErr := externalIP()
	if getIpErr != nil {
		ip.String()
		logger.Info("获取本机IP地址时，出现了错误 = %s", getIpErr)
	}

	//userName := ""

	cf := config.GetConf()
	registorHostName := cf.Name

	timeStr := time.Now().Format("2006-01-02 15:04:05")
	subject := "高危命令告警"
	body := "高危指令：" + command + "<br>" +
		"资产：" + registorHostName + "——" + ip.String() + "<br>" +
		"时间：" + timeStr

	//body :=  "用户在主机[ " + registorHostName + "——" + ip.String() + " ]上执行了高危命令[ " + command + " ]，" + timeStr

	logger.Infof("start ########## 出现高危命令啦 %s，发送邮件给管理员。", body)
	alarmServerHost := cf.AlarmServerHost
	alarmServerPort := cf.AlarmServerPort
	alarmFromEmail := cf.AlarmFromEmail
	alarmFromPasswd := cf.AlarmFromPasswd
	alarmReceiveEmail := cf.AlarmReceiveEmail

	// 结构体赋值
	myEmail := &EmailParam{
		ServerHost: alarmServerHost,
		ServerPort: alarmServerPort,
		FromEmail:  alarmFromEmail,
		// 126邮箱的授权码；
		FromPasswd: alarmFromPasswd,
		Toers:      alarmReceiveEmail,
	}

	defer func() { // 必须要先声明defer，否则不能捕获到panic异常
		InitEmail(myEmail)

		// 主题
		m.SetHeader("Subject", subject)

		// 正文
		m.SetBody("text/html", body)

		d := gomail.NewPlainDialer(serverHost, serverPort, fromEmail, fromPasswd)
		// 发送
		err := d.DialAndSend(m)
		if err != nil {
			logger.Info("发送邮件 \""+body+" \" 失败，因为出现了错误 = %s", err)
		}
	}()

	logger.Infof("end ######### 出现高危命令啦 %s，发送邮件给管理员。", body)
}

var (
	zmodemRecvStartMark = []byte("rz waiting to receive.**\x18B0100")
	zmodemSendStartMark = []byte("**\x18B00000000000000")
	zmodemCancelMark    = []byte("\x18\x18\x18\x18\x18")
	zmodemEndMark       = []byte("**\x18B0800000000022d")
	zmodemStateSend     = "send"
	zmodemStateRecv     = "recv"

	charEnter = []byte("\r")

	enterMarks = [][]byte{
		[]byte("\x1b[?1049h"),
		[]byte("\x1b[?1048h"),
		[]byte("\x1b[?1047h"),
		[]byte("\x1b[?47h"),
	}

	exitMarks = [][]byte{
		[]byte("\x1b[?1049l"),
		[]byte("\x1b[?1048l"),
		[]byte("\x1b[?1047l"),
		[]byte("\x1b[?47l"),
	}
)

const (
	CommandInputParserName  = "Command Input parser"
	CommandOutputParserName = "Command Output parser"
)

var _ ParseEngine = (*Parser)(nil)

func newParser(sid string) Parser {
	parser := Parser{id: sid}
	parser.initial()
	return parser
}

// Parse 解析用户输入输出, 拦截过滤用户输入输出
type Parser struct {
	id string

	userOutputChan chan []byte
	srvOutputChan  chan []byte
	cmdRecordChan  chan [3]string // [3]string{command, out, flag}

	inputInitial  bool
	inputPreState bool
	inputState    bool
	zmodemState   string
	inVimState    bool
	once          *sync.Once
	lock          *sync.RWMutex

	command         string
	output          string
	cmdInputParser  *CmdParser
	cmdOutputParser *CmdParser

	cmdFilterRules []model.SystemUserFilterRule
	closed         chan struct{}
}

func (p *Parser) initial() {
	p.once = new(sync.Once)
	p.lock = new(sync.RWMutex)

	p.cmdInputParser = NewCmdParser(p.id, CommandInputParserName)
	p.cmdOutputParser = NewCmdParser(p.id, CommandOutputParserName)
	p.closed = make(chan struct{})
	p.cmdRecordChan = make(chan [3]string, 1024)
}

// ParseStream 解析数据流
func (p *Parser) ParseStream(userInChan, srvInChan <-chan []byte) (userOut, srvOut <-chan []byte) {

	p.userOutputChan = make(chan []byte, 1)
	p.srvOutputChan = make(chan []byte, 1)
	logger.Infof("Session %s: Parser start", p.id)
	go func() {
		defer func() {
			// 会话结束，结算命令结果
			p.sendCommandRecord()
			close(p.cmdRecordChan)
			close(p.userOutputChan)
			close(p.srvOutputChan)
			logger.Infof("Session %s: Parser routine done", p.id)
		}()
		for {
			select {
			case <-p.closed:
				return
			case b, ok := <-userInChan:
				if !ok {
					return
				}
				b = p.ParseUserInput(b)
				select {
				case <-p.closed:
					return
				case p.userOutputChan <- b:
				}

			case b, ok := <-srvInChan:
				if !ok {
					return
				}
				b = p.ParseServerOutput(b)
				select {
				case <-p.closed:
					return
				case p.srvOutputChan <- b:
				}

			}
		}
	}()
	return p.userOutputChan, p.srvOutputChan
}
func (p *Parser) ParseStreamProxyServer(userInChan, srvInChan <-chan []byte, proxyServer *ProxyServer) (userOut, srvOut <-chan []byte) {

	p.userOutputChan = make(chan []byte, 1)
	p.srvOutputChan = make(chan []byte, 1)
	logger.Infof("Session %s: Parser start", p.id)
	go func() {
		defer func() {
			// 会话结束，结算命令结果
			p.sendCommandRecord()
			close(p.cmdRecordChan)
			close(p.userOutputChan)
			close(p.srvOutputChan)
			logger.Infof("Session %s: Parser routine done", p.id)
		}()
		for {
			select {
			case <-p.closed:
				return
			case b, ok := <-userInChan:
				if !ok {
					return
				}
				b = p.ParseUserInputProxyServer(b, proxyServer)
				select {
				case <-p.closed:
					return
				case p.userOutputChan <- b:
				}

			case b, ok := <-srvInChan:
				if !ok {
					return
				}
				b = p.ParseServerOutput(b)
				select {
				case <-p.closed:
					return
				case p.srvOutputChan <- b:
				}

			}
		}
	}()
	return p.userOutputChan, p.srvOutputChan
}

// Todo: parseMultipleInput 依然存在问题

// parseInputState 切换用户输入状态, 并结算命令和结果
func (p *Parser) parseInputState(b []byte) []byte {
	if p.inVimState || p.zmodemState != "" {
		return b
	}
	p.inputPreState = p.inputState

	if bytes.Contains(b, charEnter) {
		// 连续输入enter key, 结算上一条可能存在的命令结果
		p.sendCommandRecord()
		p.inputState = false
		// 用户输入了Enter，开始结算命令
		p.parseCmdInput()
		if cmd, ok := p.IsCommandForbidden(); !ok {
			fbdMsg := utils.WrapperWarn(fmt.Sprintf(i18n.T("Command `%s` is forbidden"), cmd))
			_, _ = p.cmdOutputParser.WriteData([]byte(fbdMsg))

			// 在这里添加高危指令告警功能，赵明
			command := p.command
			SendEmail(command)

			p.srvOutputChan <- []byte("\r\n" + fbdMsg)
			p.cmdRecordChan <- [3]string{p.command, fbdMsg, model.HighRiskFlag}
			p.command = ""
			p.output = ""
			return []byte{utils.CharCleanLine, '\r'}
		}
	} else {
		p.inputState = true
		// 用户又开始输入，并上次不处于输入状态，开始结算上次命令的结果
		if !p.inputPreState {
			p.sendCommandRecord()
		}
	}
	return b
}

// parseInputState 切换用户输入状态, 并结算命令和结果
func (p *Parser) parseInputStateProxyServer(b []byte, proxyServer *ProxyServer) []byte {
	if p.inVimState || p.zmodemState != "" {
		return b
	}
	p.inputPreState = p.inputState

	if bytes.Contains(b, charEnter) {
		// 连续输入enter key, 结算上一条可能存在的命令结果
		p.sendCommandRecord()
		p.inputState = false
		// 用户输入了Enter，开始结算命令
		p.parseCmdInput()
		if cmd, ok := p.IsCommandForbidden(); !ok {
			fbdMsg := utils.WrapperWarn(fmt.Sprintf(i18n.T("Command `%s` is forbidden"), cmd))
			_, _ = p.cmdOutputParser.WriteData([]byte(fbdMsg))

			// 在这里添加高危指令告警功能，赵明
			command := p.command
			SendEmailProxyServer(command, proxyServer)

			p.srvOutputChan <- []byte("\r\n" + fbdMsg)
			p.cmdRecordChan <- [3]string{p.command, fbdMsg, model.HighRiskFlag}
			p.command = ""
			p.output = ""
			return []byte{utils.CharCleanLine, '\r'}
		}
	} else {
		p.inputState = true
		// 用户又开始输入，并上次不处于输入状态，开始结算上次命令的结果
		if !p.inputPreState {
			p.sendCommandRecord()
		}
	}
	return b
}

// parseCmdInput 解析命令的输入
func (p *Parser) parseCmdInput() {
	p.command = p.cmdInputParser.Parse()
}

// parseCmdOutput 解析命令输出
func (p *Parser) parseCmdOutput() {
	p.output = p.cmdOutputParser.Parse()
}

// ParseUserInput 解析用户的输入
func (p *Parser) ParseUserInput(b []byte) []byte {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.once.Do(func() {
		p.inputInitial = true
	})
	nb := p.parseInputState(b)
	return nb
} // ParseUserInput 解析用户的输入
func (p *Parser) ParseUserInputProxyServer(b []byte, proxyServer *ProxyServer) []byte {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.once.Do(func() {
		p.inputInitial = true
	})
	nb := p.parseInputStateProxyServer(b, proxyServer)
	return nb
}

// parseZmodemState 解析数据，查看是不是处于zmodem状态
// 处于zmodem状态不会再解析命令
func (p *Parser) parseZmodemState(b []byte) {
	if len(b) < 20 {
		return
	}
	if p.zmodemState == "" {
		if len(b) > 25 && bytes.Contains(b[:50], zmodemRecvStartMark) {
			p.zmodemState = zmodemStateRecv
			logger.Debug("Zmodem in recv state")
		} else if bytes.Contains(b[:24], zmodemSendStartMark) {
			p.zmodemState = zmodemStateSend
			logger.Debug("Zmodem in send state")
		}
	} else {
		if bytes.Contains(b[:24], zmodemEndMark) {
			logger.Debug("Zmodem end")
			p.zmodemState = ""
		} else if bytes.Contains(b, zmodemCancelMark) {
			logger.Debug("Zmodem cancel")
			p.zmodemState = ""
		}
	}
}

// parseVimState 解析vim的状态，处于vim状态中，里面输入的命令不再记录
func (p *Parser) parseVimState(b []byte) {
	if p.zmodemState == "" && !p.inVimState && IsEditEnterMode(b) {
		p.inVimState = true
		logger.Debug("In vim state: true")
	}
	if p.zmodemState == "" && p.inVimState && IsEditExitMode(b) {
		p.inVimState = false
		logger.Debug("In vim state: false")
	}
}

// splitCmdStream 将服务器输出流分离到命令buffer和命令输出buffer
func (p *Parser) splitCmdStream(b []byte) {
	p.parseVimState(b)
	p.parseZmodemState(b)
	if p.zmodemState != "" || p.inVimState || !p.inputInitial {
		return
	}
	if p.inputState {
		_, _ = p.cmdInputParser.WriteData(b)
		return
	}
	_, _ = p.cmdOutputParser.WriteData(b)
}

// ParseServerOutput 解析服务器输出
func (p *Parser) ParseServerOutput(b []byte) []byte {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.splitCmdStream(b)
	return b
}

// SetCMDFilterRules 设置命令过滤规则
func (p *Parser) SetCMDFilterRules(rules []model.SystemUserFilterRule) {
	p.cmdFilterRules = rules
}

// IsCommandForbidden 判断命令是不是在过滤规则中
func (p *Parser) IsCommandForbidden() (string, bool) {
	for _, rule := range p.cmdFilterRules {
		allowed, cmd := rule.Match(p.command)
		switch allowed {
		case model.ActionAllow:
			return "", true
		case model.ActionDeny:
			return cmd, false
		default:

		}
	}
	return "", true
}

func (p *Parser) IsInZmodemRecvState() bool {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.zmodemState != ""
}

// Close 关闭parser
func (p *Parser) Close() {
	select {
	case <-p.closed:
		return
	default:
		close(p.closed)

	}
	_ = p.cmdOutputParser.Close()
	_ = p.cmdInputParser.Close()
	logger.Infof("Session %s: Parser close", p.id)
}

func (p *Parser) sendCommandRecord() {
	if p.command != "" {
		p.parseCmdOutput()
		p.cmdRecordChan <- [3]string{p.command, p.output, model.LessRiskFlag}
		p.command = ""
		p.output = ""
	}
}

func (p *Parser) NeedRecord() bool {
	return !p.IsInZmodemRecvState()
}

func (p *Parser) CommandRecordChan() chan [3]string {
	return p.cmdRecordChan
}

func IsEditEnterMode(p []byte) bool {
	return matchMark(p, enterMarks)
}

func IsEditExitMode(p []byte) bool {
	return matchMark(p, exitMarks)
}

func matchMark(p []byte, marks [][]byte) bool {
	for _, item := range marks {
		if bytes.Contains(p, item) {
			return true
		}
	}
	return false
}
