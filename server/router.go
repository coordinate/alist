package server

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/coordinate/alist/cmd/flags"
	"github.com/coordinate/alist/internal/conf"
	"github.com/coordinate/alist/internal/message"
	"github.com/coordinate/alist/pkg/utils"
	"github.com/coordinate/alist/server/common"
	"github.com/coordinate/alist/server/encrypt"
	"github.com/coordinate/alist/server/handles"
	"github.com/coordinate/alist/server/middlewares"
	"github.com/coordinate/alist/server/static"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// *******************************************
func videoProxyHandler(w http.ResponseWriter, r *http.Request, videoURL string, fileSize int) {
	// Create a new HTTP request to the video URL
	req, err := http.NewRequest(r.Method, videoURL, nil)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Copy headers from the original request
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Send the request to the video URL
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error fetching video", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy the headers from the video response to the response writer
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Create a pipe to stream data
	pipeReader, pipeWriter := io.Pipe()
	defer pipeReader.Close()
	defer pipeWriter.Close()

	rangeHeader := resp.Request.Header.Get("Range")
	var start int = 0
	// 解析 Range 头
	parts := strings.Split(rangeHeader, "=")
	if len(parts) > 1 && len(parts[1]) > 0 {
		rangeValues := strings.Split(parts[1], "-")
		if len(rangeValues) > 0 {
			// 将开始字节转换为整数
			if startVal, err := strconv.ParseInt(rangeValues[0], 10, 64); err == nil {
				start = int(startVal)
			}
		}
	}
	encryptFlow, _ := encrypt.NewAesCTR("111500", fileSize)
	if start > 0 {
		fmt.Print(start)
		encryptFlow.SetPosition(start)
	}

	// Start a goroutine to read from the video response and decrypt the data
	go func() {
		defer pipeWriter.Close()
		bufferSize := 1024 * 64 // 64KB buffer
		buffer := make([]byte, bufferSize)
		for {
			n, err := resp.Body.Read(buffer)
			// if n >= 65536 || n <= 0 {
			// 	fmt.Println("????????????????????")
			// 	return
			// }
			if err != nil && err != io.EOF {
				fmt.Println("Error reading video response:", err)
				return
			}
			decryptedData := encryptFlow.Decrypt(buffer[:n])
			if _, err := pipeWriter.Write(decryptedData); err != nil {
				fmt.Println("Error writing to pipe:", err)
				return
			}
			if err != nil && err == io.EOF {
				return
			}
		}
	}()

	// Stream the decrypted data from the pipe to the response writer
	if _, err := io.Copy(w, pipeReader); err != nil {
		fmt.Println("Error writing to response:", err)
	} else {
		fmt.Println("Writing to response...")
	}
}

// *******************************************

func Init(e *gin.Engine) {
	if !utils.SliceContains([]string{"", "/"}, conf.URL.Path) {
		e.GET("/", func(c *gin.Context) {
			c.Redirect(302, conf.URL.Path)
		})
	}
	Cors(e)
	g := e.Group(conf.URL.Path)
	if conf.Conf.Scheme.HttpPort != -1 && conf.Conf.Scheme.HttpsPort != -1 && conf.Conf.Scheme.ForceHttps {
		e.Use(middlewares.ForceHttps)
	}
	// *******************************************
	g.Any("/redirect/*key", func(c *gin.Context) {
		key := c.Param("key")
		value, _ := encrypt.RawURLCache.Get(key[1:])
		parts := strings.SplitN(value.(string), "http", 2)
		size, _ := strconv.Atoi(parts[0])
		rawUrl := "http" + parts[1]
		// fmt.Print(size)
		// fmt.Print(rawUrl)
		// proxy, _ := NewProxy(rawUrl, size)
		// proxy.ServeHTTP(c.Writer, c.Request)
		// httpProxy(c.Writer, c.Request, rawUrl)
		videoProxyHandler(c.Writer, c.Request, rawUrl, size)
	})
	// *******************************************
	g.Any("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	g.GET("/favicon.ico", handles.Favicon)
	g.GET("/robots.txt", handles.Robots)
	g.GET("/i/:link_name", handles.Plist)
	common.SecretKey = []byte(conf.Conf.JwtSecret)
	g.Use(middlewares.StoragesLoaded)
	if conf.Conf.MaxConnections > 0 {
		g.Use(middlewares.MaxAllowed(conf.Conf.MaxConnections))
	}
	WebDav(g.Group("/dav"))
	S3(g.Group("/s3"))

	g.GET("/d/*path", middlewares.Down, handles.Down)
	g.GET("/p/*path", middlewares.Down, handles.Proxy)
	g.HEAD("/d/*path", middlewares.Down, handles.Down)
	g.HEAD("/p/*path", middlewares.Down, handles.Proxy)

	api := g.Group("/api")
	auth := api.Group("", middlewares.Auth)
	webauthn := api.Group("/authn", middlewares.Authn)

	api.POST("/auth/login", handles.Login)
	api.POST("/auth/login/hash", handles.LoginHash)
	api.POST("/auth/login/ldap", handles.LoginLdap)
	auth.GET("/me", handles.CurrentUser)
	auth.POST("/me/update", handles.UpdateCurrent)
	auth.POST("/auth/2fa/generate", handles.Generate2FA)
	auth.POST("/auth/2fa/verify", handles.Verify2FA)
	auth.GET("/auth/logout", handles.LogOut)

	// auth
	api.GET("/auth/sso", handles.SSOLoginRedirect)
	api.GET("/auth/sso_callback", handles.SSOLoginCallback)
	api.GET("/auth/get_sso_id", handles.SSOLoginCallback)
	api.GET("/auth/sso_get_token", handles.SSOLoginCallback)

	// webauthn
	webauthn.GET("/webauthn_begin_registration", handles.BeginAuthnRegistration)
	webauthn.POST("/webauthn_finish_registration", handles.FinishAuthnRegistration)
	webauthn.GET("/webauthn_begin_login", handles.BeginAuthnLogin)
	webauthn.POST("/webauthn_finish_login", handles.FinishAuthnLogin)
	webauthn.POST("/delete_authn", handles.DeleteAuthnLogin)
	webauthn.GET("/getcredentials", handles.GetAuthnCredentials)

	// no need auth
	public := api.Group("/public")
	public.Any("/settings", handles.PublicSettings)
	public.Any("/offline_download_tools", handles.OfflineDownloadTools)

	_fs(auth.Group("/fs"))
	_task(auth.Group("/task", middlewares.AuthNotGuest))
	admin(auth.Group("/admin", middlewares.AuthAdmin))
	if flags.Debug || flags.Dev {
		debug(g.Group("/debug"))
	}
	static.Static(g, func(handlers ...gin.HandlerFunc) {
		e.NoRoute(handlers...)
	})
}

func admin(g *gin.RouterGroup) {
	meta := g.Group("/meta")
	meta.GET("/list", handles.ListMetas)
	meta.GET("/get", handles.GetMeta)
	meta.POST("/create", handles.CreateMeta)
	meta.POST("/update", handles.UpdateMeta)
	meta.POST("/delete", handles.DeleteMeta)

	user := g.Group("/user")
	user.GET("/list", handles.ListUsers)
	user.GET("/get", handles.GetUser)
	user.POST("/create", handles.CreateUser)
	user.POST("/update", handles.UpdateUser)
	user.POST("/cancel_2fa", handles.Cancel2FAById)
	user.POST("/delete", handles.DeleteUser)
	user.POST("/del_cache", handles.DelUserCache)

	storage := g.Group("/storage")
	storage.GET("/list", handles.ListStorages)
	storage.GET("/get", handles.GetStorage)
	storage.POST("/create", handles.CreateStorage)
	storage.POST("/update", handles.UpdateStorage)
	storage.POST("/delete", handles.DeleteStorage)
	storage.POST("/enable", handles.EnableStorage)
	storage.POST("/disable", handles.DisableStorage)
	storage.POST("/load_all", handles.LoadAllStorages)

	driver := g.Group("/driver")
	driver.GET("/list", handles.ListDriverInfo)
	driver.GET("/names", handles.ListDriverNames)
	driver.GET("/info", handles.GetDriverInfo)

	setting := g.Group("/setting")
	setting.GET("/get", handles.GetSetting)
	setting.GET("/list", handles.ListSettings)
	setting.POST("/save", handles.SaveSettings)
	setting.POST("/delete", handles.DeleteSetting)
	setting.POST("/reset_token", handles.ResetToken)
	setting.POST("/set_aria2", handles.SetAria2)
	setting.POST("/set_qbit", handles.SetQbittorrent)
	setting.POST("/set_transmission", handles.SetTransmission)

	// retain /admin/task API to ensure compatibility with legacy automation scripts
	_task(g.Group("/task"))

	ms := g.Group("/message")
	ms.POST("/get", message.HttpInstance.GetHandle)
	ms.POST("/send", message.HttpInstance.SendHandle)

	index := g.Group("/index")
	index.POST("/build", middlewares.SearchIndex, handles.BuildIndex)
	index.POST("/update", middlewares.SearchIndex, handles.UpdateIndex)
	index.POST("/stop", middlewares.SearchIndex, handles.StopIndex)
	index.POST("/clear", middlewares.SearchIndex, handles.ClearIndex)
	index.GET("/progress", middlewares.SearchIndex, handles.GetProgress)
}

func _fs(g *gin.RouterGroup) {
	g.Any("/list", handles.FsList)
	g.Any("/search", middlewares.SearchIndex, handles.Search)
	g.Any("/get", handles.FsGet)
	g.Any("/other", handles.FsOther)
	g.Any("/dirs", handles.FsDirs)
	g.POST("/mkdir", handles.FsMkdir)
	g.POST("/rename", handles.FsRename)
	g.POST("/batch_rename", handles.FsBatchRename)
	g.POST("/regex_rename", handles.FsRegexRename)
	g.POST("/move", handles.FsMove)
	g.POST("/recursive_move", handles.FsRecursiveMove)
	g.POST("/copy", handles.FsCopy)
	g.POST("/remove", handles.FsRemove)
	g.POST("/remove_empty_directory", handles.FsRemoveEmptyDirectory)
	g.PUT("/put", middlewares.FsUp, handles.FsStream)
	g.PUT("/form", middlewares.FsUp, handles.FsForm)
	g.POST("/link", middlewares.AuthAdmin, handles.Link)
	// g.POST("/add_aria2", handles.AddOfflineDownload)
	// g.POST("/add_qbit", handles.AddQbittorrent)
	// g.POST("/add_transmission", handles.SetTransmission)
	g.POST("/add_offline_download", handles.AddOfflineDownload)
}

func _task(g *gin.RouterGroup) {
	handles.SetupTaskRoute(g)
}

func Cors(r *gin.Engine) {
	config := cors.DefaultConfig()
	// config.AllowAllOrigins = true
	config.AllowOrigins = conf.Conf.Cors.AllowOrigins
	config.AllowHeaders = conf.Conf.Cors.AllowHeaders
	config.AllowMethods = conf.Conf.Cors.AllowMethods
	r.Use(cors.New(config))
}

func InitS3(e *gin.Engine) {
	Cors(e)
	S3Server(e.Group("/"))
}
