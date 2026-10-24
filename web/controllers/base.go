package controllers

import (
	"fmt"
	"html"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/bridge"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/crypt"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/version"
	"ehang.io/nps/server"
	"github.com/astaxie/beego"
)

// WebDomain 一个候选域名，带该域名对应的证书/私钥路径（路径可以为空）
type WebDomain struct {
	Name string
	Cert string
	Key  string
}

// 域名形态校验：example.com、*.example.com、a-b.example.com
var webDomainRe = regexp.MustCompile(`^(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$`)

// getWebDomains 读取 nps.conf 里的候选后缀，供「新增/编辑主机」下拉选择。
//
// 推荐写法（一行一个，普通键值，不会影响其它配置项）：
//
//	web_domain_1=*.a.com
//	web_domain_1_cert=/conf/cert/a.com.pem
//	web_domain_1_key=/conf/cert/a.com.key
//	web_domain_2=plain.com
//
// 兼容旧的 [web_domains] 段写法，但 ini 里段之后的所有键都会归到该段，
// 段一旦不在文件末尾，后面的 web_port / tls_enable 等配置就会失效，所以只做兼容不再推荐。
func getWebDomains() []WebDomain {
	seen := make(map[string]bool)
	domains := make([]WebDomain, 0, 4)
	add := func(name, cert, key string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || !webDomainRe.MatchString(name) {
			return
		}
		seen[name] = true
		domains = append(domains, WebDomain{Name: name, Cert: strings.TrimSpace(cert), Key: strings.TrimSpace(key)})
	}

	// 1) web_domain_N（推荐）
	for i := 1; i <= 50; i++ {
		prefix := fmt.Sprintf("web_domain_%d", i)
		name := beego.AppConfig.String(prefix)
		if strings.TrimSpace(name) == "" {
			continue
		}
		add(name, beego.AppConfig.String(prefix+"_cert"), beego.AppConfig.String(prefix+"_key"))
	}
	if len(domains) > 0 {
		return domains
	}

	// 2) [web_domains] 段（兼容，且过滤掉被 ini 误并进来的普通配置键）
	if section, err := beego.AppConfig.GetSection("web_domains"); err == nil && len(section) > 0 {
		names := make([]string, 0, len(section))
		for name := range section {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			d := WebDomain{Name: strings.TrimSpace(name)}
			parts := strings.Split(section[name], ",")
			if len(parts) > 0 {
				d.Cert = strings.TrimSpace(parts[0])
			}
			if len(parts) > 1 {
				d.Key = strings.TrimSpace(parts[1])
			}
			add(d.Name, d.Cert, d.Key)
		}
		if len(domains) > 0 {
			return domains
		}
	}

	// 3) 更老的逗号写法：web_domains=a.com,b.com
	for _, part := range strings.Split(beego.AppConfig.String("web_domains"), ",") {
		add(part, "", "")
	}
	return domains
}

type BaseController struct {
	beego.Controller
	controllerName string
	actionName     string
}

// 初始化参数
func (s *BaseController) Prepare() {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	controllerName, actionName := s.GetControllerAndAction()
	s.controllerName = strings.ToLower(controllerName[0 : len(controllerName)-10])
	s.actionName = strings.ToLower(actionName)
	// web api verify
	// param 1 is md5(authKey+Current timestamp)
	// param 2 is timestamp (It's limited to 20 seconds.)
	md5Key := s.getEscapeString("auth_key")
	timestamp := s.GetIntNoErr("timestamp")
	configKey := beego.AppConfig.String("auth_key")
	if configKey == "" {
		configKey = crypt.GetRandomString(64)
	}
	timeNowUnix := time.Now().Unix()
	if !(md5Key != "" && (math.Abs(float64(timeNowUnix-int64(timestamp))) <= 20) && (crypt.Md5(configKey+strconv.Itoa(timestamp)) == md5Key)) {
		if s.GetSession("auth") != true {
			s.Redirect(beego.AppConfig.String("web_base_url")+"/login/index", 302)
		}
	} else {
		s.SetSession("isAdmin", true)
		s.Data["isAdmin"] = true
	}
	if s.GetSession("isAdmin") != nil && !s.GetSession("isAdmin").(bool) {
		s.Ctx.Input.SetData("client_id", s.GetSession("clientId").(int))
		s.Ctx.Input.SetParam("client_id", strconv.Itoa(s.GetSession("clientId").(int)))
		s.Data["isAdmin"] = false
		s.Data["username"] = s.GetSession("username")
		s.CheckUserAuth()
	} else {
		s.Data["isAdmin"] = true
	}
	s.Data["allow_user_login"], _ = beego.AppConfig.Bool("allow_user_login")
	s.Data["allow_flow_limit"], _ = beego.AppConfig.Bool("allow_flow_limit")
	s.Data["allow_rate_limit"], _ = beego.AppConfig.Bool("allow_rate_limit")
	s.Data["allow_connection_num_limit"], _ = beego.AppConfig.Bool("allow_connection_num_limit")
	s.Data["allow_multi_ip"], _ = beego.AppConfig.Bool("allow_multi_ip")
	s.Data["system_info_display"], _ = beego.AppConfig.Bool("system_info_display")
	s.Data["allow_tunnel_num_limit"], _ = beego.AppConfig.Bool("allow_tunnel_num_limit")
	s.Data["allow_local_proxy"], _ = beego.AppConfig.Bool("allow_local_proxy")
	s.Data["allow_user_change_username"], _ = beego.AppConfig.Bool("allow_user_change_username")
	showHttpProxyPort := beego.AppConfig.DefaultBool("show_http_proxy_port", true)
	httpPort := beego.AppConfig.String("http_proxy_port")
	if httpPort != "80" && showHttpProxyPort {
		s.Data["http_proxy_port"] = ":" + httpPort
	}
}

// 加载模板
func (s *BaseController) display(tpl ...string) {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	var tplname string
	if s.Data["menu"] == nil {
		s.Data["menu"] = s.actionName
	}
	if len(tpl) > 0 {
		tplname = strings.Join([]string{tpl[0], "html"}, ".")
	} else {
		tplname = s.controllerName + "/" + s.actionName + ".html"
	}
	ip := s.Ctx.Request.Host
	s.Data["ip"] = common.GetIpByAddr(ip)

	global := file.GetDb().GetGlobal()
	if global != nil && global.ServerUrl != "" && global.ServerUrl != ip {
		// 替换掉 http:// 或者 https://
		ip = global.ServerUrl
		ip = strings.ReplaceAll(ip, "http://", "")
		ip = strings.ReplaceAll(ip, "https://", "")
		s.Data["ip"] = ip
	}

	s.Data["bridgeType"] = beego.AppConfig.String("bridge_type")
	if common.IsWindows() {
		s.Data["win"] = "npc.exe"
	} else {
		s.Data["win"] = "./npc"
	}

	s.Data["p"] = strconv.Itoa(server.Bridge.TunnelPort)
	s.Data["version"] = version.VERSION

	if bridge.ServerTlsEnable {
		tlsPort := strconv.Itoa(beego.AppConfig.DefaultInt("tls_bridge_port", 8025))
		s.Data["tls_p"] = tlsPort
		s.Data["tls_enable"] = true
		s.Data["p1"] = strconv.Itoa(server.Bridge.TunnelPort) + " / " + tlsPort
	} else {
		s.Data["tls_enable"] = false
		s.Data["p1"] = strconv.Itoa(server.Bridge.TunnelPort)
	}

	s.Data["proxyPort"] = beego.AppConfig.String("hostPort")
	s.Layout = "public/layout.html"
	s.TplName = tplname
}

// 错误
func (s *BaseController) error() {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	s.Layout = "public/layout.html"
	s.TplName = "public/error.html"
}

// getEscapeString
func (s *BaseController) getEscapeString(key string) string {
	return html.EscapeString(s.GetString(key))
}

// 去掉没有err返回值的int
func (s *BaseController) GetIntNoErr(key string, def ...int) int {
	strv := s.Ctx.Input.Query(key)
	if len(strv) == 0 && len(def) > 0 {
		return def[0]
	}
	val, _ := strconv.Atoi(strv)
	return val
}

// 获取去掉错误的bool值
func (s *BaseController) GetBoolNoErr(key string, def ...bool) bool {
	strv := s.Ctx.Input.Query(key)
	if len(strv) == 0 && len(def) > 0 {
		return def[0]
	}
	val, _ := strconv.ParseBool(strv)
	return val
}

// ajax正确返回
func (s *BaseController) AjaxOk(str string) {
	s.Data["json"] = ajax(str, 1)
	s.ServeJSON()
	s.StopRun()
}

// ajax正确返回
func (s *BaseController) AjaxOkWithId(str string, id int) {
	s.Data["json"] = ajaxWithId(str, 1, id)
	s.ServeJSON()
	s.StopRun()
}

// ajax错误返回
func (s *BaseController) AjaxErr(str string) {
	s.Data["json"] = ajax(str, 0)
	s.ServeJSON()
	s.StopRun()
}

// 组装ajax
func ajax(str string, status int) map[string]interface{} {
	json := make(map[string]interface{})
	json["status"] = status
	json["msg"] = str
	return json
}

// 组装ajax
func ajaxWithId(str string, status int, id int) map[string]interface{} {
	json := make(map[string]interface{})
	json["status"] = status
	json["msg"] = str
	json["id"] = id
	return json
}

// ajax table返回
func (s *BaseController) AjaxTable(list interface{}, cnt int, recordsTotal int, kwargs map[string]interface{}) {
	json := make(map[string]interface{})
	json["rows"] = list
	json["total"] = recordsTotal
	if kwargs != nil {
		for k, v := range kwargs {
			if v != nil {
				json[k] = v
			}
		}
	}
	s.Data["json"] = json
	s.ServeJSON()
	s.StopRun()
}

// ajax table参数
func (s *BaseController) GetAjaxParams() (start, limit int) {
	return s.GetIntNoErr("offset"), s.GetIntNoErr("limit")
}

func (s *BaseController) SetInfo(name string) {
	s.Data["name"] = name
}

func (s *BaseController) SetType(name string) {
	s.Data["type"] = name
}

func (s *BaseController) CheckUserAuth() {
	if s.controllerName == "client" {
		if s.actionName == "add" {
			s.StopRun()
			return
		}
		if id := s.GetIntNoErr("id"); id != 0 {
			if id != s.GetSession("clientId").(int) {
				s.StopRun()
				return
			}
		}
	}
	if s.controllerName == "index" {
		if id := s.GetIntNoErr("id"); id != 0 {
			belong := false
			if strings.Contains(s.actionName, "h") {
				if v, ok := file.GetDb().JsonDb.Hosts.Load(id); ok {
					if v.(*file.Host).Client.Id == s.GetSession("clientId").(int) {
						belong = true
					}
				}
			} else {
				if v, ok := file.GetDb().JsonDb.Tasks.Load(id); ok {
					if v.(*file.Tunnel).Client.Id == s.GetSession("clientId").(int) {
						belong = true
					}
				}
			}
			if !belong {
				s.StopRun()
			}
		}
	}
}
