package common

const (
	CONN_DATA_SEQ     = "*#*" //Separator
	VERIFY_EER        = "vkey"
	VERIFY_SUCCESS    = "sucs"
	WORK_MAIN         = "main"
	WORK_CHAN         = "chan"
	WORK_CONFIG       = "conf"
	WORK_REGISTER     = "rgst"
	WORK_SECRET       = "sert"
	WORK_FILE         = "file"
	WORK_P2P          = "p2pm"
	WORK_P2P_VISITOR  = "p2pv"
	WORK_P2P_PROVIDER = "p2pp"
	WORK_P2P_CONNECT  = "p2pc"
	WORK_P2P_SUCCESS  = "p2ps"
	WORK_P2P_END      = "p2pe"
	WORK_P2P_LAST     = "p2pl"
	WORK_STATUS       = "stus"
	RES_MSG           = "msg0"
	RES_CLOSE         = "clse"
	NEW_UDP_CONN      = "udpc" //p2p udp conn
	// REPORT_LOCAL_IP: server requests client local/private IPs on WORK_MAIN.
	// New clients reply with WriteLenContent; old clients ignore the flag (server times out).
	REPORT_LOCAL_IP = "rlip"
	NEW_TASK        = "task"
	NEW_CONF        = "conf"
	NEW_HOST        = "host"
	CONN_TCP        = "tcp"
	CONN_UDP        = "udp"
	CONN_TEST       = "TST"
	// UnauthorizedBytes is the challenge for reverse-proxy hosts.
	// It must be a well-formed HTTP/1.1 response: CDN origins reject bare-LF
	// responses without Content-Length, so the header block uses CRLF and the
	// body length is declared explicitly.
	UnauthorizedBytes = "HTTP/1.1 401 Unauthorized\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"WWW-Authenticate: Basic realm=\"easyProxy\"\r\n" +
		"Content-Length: 16\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"401 Unauthorized"
	// ProxyAuthRequiredBytes is the challenge for HTTP forward proxy Basic auth (RFC 7235).
	// Clients expect 407 + Proxy-Authenticate, not 401 + WWW-Authenticate.
	ProxyAuthRequiredBytes = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Proxy-Authenticate: Basic realm=\"nps\"\r\n" +
		"\r\n" +
		"407 Proxy Authentication Required"
	ConnectionFailBytes = `HTTP/1.1 404 Not Found

`
	Unauthorized = `HTTP/1.1 401 Unauthorized

`
)
