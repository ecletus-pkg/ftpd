package ftpd

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"sync/atomic"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"github.com/fclairamb/ftpserver/server"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/jinzhu/configor"
	"github.com/mitchellh/go-homedir"
	"github.com/moisespsena/go-error-wrap"
	"github.com/moisespsena/go-path-helpers"
)

// MainDriver defines a very basic ftpserver driver
type MainDriver struct {
	Logger       log.Logger  // Logger
	SettingsFile string      // Settings file
	BaseDir      string      // Base directory from which to serve file
	tlsConfig    *tls.Config // TLS Config (if applies)
	Config       Config      // Our settings
	nbClients    int32       // Number of clients
}

// ClientDriver defines a very basic client driver
type ClientDriver struct {
	BaseDir string // Base directory from which to server file
}

// Account defines a user/pass password
type Account struct {
	User string // Username
	Pass string // Password
	Dir  string // Directory
}

type ServerSettings struct {
	AutoStart bool
	RootDir   string

	ListenAddr                string           // Listening address
	PublicHost                string           // Public IP to expose (only an IP address is accepted at this stage)
	DataPortRange             *server.PortRange       // Port Range for data connections. Random one will be used if not specified
	DisableMLSD               bool             // Disable MLSD support
	DisableMLST               bool             // Disable MLST support
	NonStandardActiveDataPort bool             // Allow to use a non-standard active data port
	IdleTimeout               int
}

// Config defines our settings
type Config struct {
	Server         ServerSettings // Server settings (shouldn't need to be filled)
	Users          []Account      // Credentials
	MaxConnections int32          // Maximum number of clients that are allowed to connect at the same time
}

// GetSettings returns some general settings around the server setup
func (driver *MainDriver) GetSettings() (err error) {
	//var Config Config
	if err = configor.Load(&driver.Config, driver.SettingsFile); err != nil && !os.IsNotExist(err) {
		err = errwrap.Wrap(err, "Load Config file %q", driver.SettingsFile)
		return
	}

	if driver.BaseDir, err = homedir.Expand(driver.Config.Server.RootDir); err != nil {
		err = errwrap.Wrap(err, "Expand homedir %q", driver.Config.Server.RootDir)
		return
	}

	// This is the new IP loading change coming from Ray
	if driver.Config.Server.PublicHost == "" {
		level.Debug(driver.Logger).Log("msg", "Fetching our external IP address...")
		if driver.Config.Server.PublicHost, err = externalIP(); err != nil {
			level.Warn(driver.Logger).Log("msg", "Couldn't fetch an external IP", "err", err)
		} else {
			level.Debug(driver.Logger).Log("msg", "Fetched our external IP address", "ipAddress", driver.Config.Server.PublicHost)
		}
	}

	if len(driver.Config.Users) == 0 {
		return errors.New("you must have at least one user defined")
	}

	return nil
}

// GetTLSConfig returns a TLS Certificate to use
func (driver *MainDriver) GetTLSConfig() (*tls.Config, error) {
	if driver.tlsConfig == nil {
		level.Info(driver.Logger).Log("msg", "Loading certificate")
		if cert, err := driver.getCertificate(); err == nil {
			driver.tlsConfig = &tls.Config{
				NextProtos:   []string{"ftp"},
				Certificates: []tls.Certificate{*cert},
			}
		} else {
			return nil, err
		}
	}
	return driver.tlsConfig, nil
}

// Live generation of a self-signed certificate
// This implementation of the driver doesn't load a certificate from a file on purpose. But it any proper implementation
// should most probably load the certificate from a file using tls.LoadX509KeyPair("cert_pub.pem", "cert_priv.pem").
func (driver *MainDriver) getCertificate() (*tls.Certificate, error) {
	level.Info(driver.Logger).Log("msg", "Creating certificate")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		level.Error(driver.Logger).Log("msg", "Could not generate key", "err", err)
		return nil, err
	}

	now := time.Now().UTC()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"FTPServer"},
		},
		DNSNames:              []string{"localhost"},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour * 24 * 7),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	if err != nil {
		level.Error(driver.Logger).Log("msg", "Could not create cert", "err", err)
		return nil, err
	}

	var certPem, keyPem bytes.Buffer
	if err := pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}
	if err := pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())
	return &c, err
}

// WelcomeUser is called to send the very first welcome message
func (driver *MainDriver) WelcomeUser(cc server.ClientContext) (string, error) {
	nbClients := atomic.AddInt32(&driver.nbClients, 1)
	if nbClients > driver.Config.MaxConnections {
		return "Cannot accept any additional client", fmt.Errorf("too many clients: %d > % d", driver.nbClients, driver.Config.MaxConnections)
	}

	cc.SetDebug(true)
	// This will remain the official name for now
	return fmt.Sprintf(
			"Welcome on ftpserver, you're on dir %s, your ID is %d, your IP:port is %s, we currently have %d clients connected",
			driver.BaseDir,
			cc.ID(),
			cc.RemoteAddr(),
			nbClients),
		nil
}

// AuthUser authenticates the user and selects an handling driver
func (driver *MainDriver) AuthUser(cc server.ClientContext, user, pass string) (server.ClientHandlingDriver, error) {
	for _, act := range driver.Config.Users {
		if act.User == user && act.Pass == pass {
			// If we are authenticated, we can return a client driver containing *our* basedir
			baseDir := driver.BaseDir + string(os.PathSeparator) + act.Dir
			perms, err := path_helpers.ResolvPerms(baseDir)
			if err != nil {
				return nil, errwrap.Wrap(err, "Resolv perms of %q", baseDir)
			}
			os.MkdirAll(baseDir, os.FileMode(perms))
			return &ClientDriver{BaseDir: baseDir}, nil
		}
	}

	return nil, fmt.Errorf("could not authenticate you")
}

// UserLeft is called when the user disconnects, even if he never authenticated
func (driver *MainDriver) UserLeft(cc server.ClientContext) {
	atomic.AddInt32(&driver.nbClients, -1)
}

// ChangeDirectory changes the current working directory
func (driver *ClientDriver) ChangeDirectory(cc server.ClientContext, directory string) error {
	if directory == "/debug" {
		cc.SetDebug(!cc.Debug())
		return nil
	}
	_, err := os.Stat(driver.BaseDir + directory)
	return err
}

// MakeDirectory creates a directory
func (driver *ClientDriver) MakeDirectory(cc server.ClientContext, directory string) error {
	perms, err := path_helpers.ResolvPerms(driver.BaseDir)
	if err != nil {
		return errwrap.Wrap(err, "Resolv perms of %q", driver.BaseDir)
	}
	return os.Mkdir(driver.BaseDir+directory, os.FileMode(perms))
}

// ListFiles lists the files of a directory
func (driver *ClientDriver) ListFiles(cc server.ClientContext) ([]os.FileInfo, error) {
	if cc.Path() == "/debug" {
		return make([]os.FileInfo, 0), nil
	}

	path := driver.BaseDir + cc.Path()
	return ioutil.ReadDir(path)
}

// OpenFile opens a file in 3 possible modes: read, write, appending write (use appropriate flags)
func (driver *ClientDriver) OpenFile(cc server.ClientContext, path string, flag int) (server.FileStream, error) {
	path = driver.BaseDir + path

	// If we are writing and we are not in append mode, we should remove the file
	if (flag & os.O_WRONLY) != 0 {
		flag |= os.O_CREATE
		if (flag & os.O_APPEND) == 0 {
			os.Remove(path)
		}
	}

	perms, err := path_helpers.ResolvFilePerms(path)
	if err != nil {
		return nil, errwrap.Wrap(err, "Resolv perms of %q", path)
	}

	return os.OpenFile(path, flag, os.FileMode(perms))
}

// GetFileInfo gets some info around a file or a directory
func (driver *ClientDriver) GetFileInfo(cc server.ClientContext, path string) (os.FileInfo, error) {
	switch path {
	case "/debug":
		return &virtualFileInfo{name: "debug", size: 4096, mode: os.ModeDir}, nil
	}

	path = driver.BaseDir + path

	return os.Stat(path)
}

// CanAllocate gives the approval to allocate some data
func (driver *ClientDriver) CanAllocate(cc server.ClientContext, size int) (bool, error) {
	return true, nil
}

// ChmodFile changes the attributes of the file
func (driver *ClientDriver) ChmodFile(cc server.ClientContext, path string, mode os.FileMode) error {
	path = driver.BaseDir + path
	return os.Chmod(path, mode)
}

// DeleteFile deletes a file or a directory
func (driver *ClientDriver) DeleteFile(cc server.ClientContext, path string) error {
	path = driver.BaseDir + path
	return os.Remove(path)
}

// RenameFile renames a file or a directory
func (driver *ClientDriver) RenameFile(cc server.ClientContext, from, to string) error {
	from = driver.BaseDir + from
	to = driver.BaseDir + to
	return os.Rename(from, to)
}

// NewSampleDriver creates a sample driver
func New(settingsFile string) *MainDriver {
	drv := &MainDriver{
		Logger:       log.NewNopLogger(),
		SettingsFile: settingsFile,
	}

	return drv
}

type virtualFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f virtualFileInfo) Name() string {
	return f.name
}

func (f virtualFileInfo) Size() int64 {
	return f.size
}

func (f virtualFileInfo) Mode() os.FileMode {
	return f.mode
}

func (f virtualFileInfo) IsDir() bool {
	return f.mode.IsDir()
}

func (f virtualFileInfo) ModTime() time.Time {
	return time.Now().UTC()
}

func (f virtualFileInfo) Sys() interface{} {
	return nil
}

func externalIP() (string, error) {
	// If you need to take a bet, amazon is about as reliable & sustainable a service as you can get
	rsp, err := http.Get("http://checkip.amazonaws.com")
	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()

	buf, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return "", err
	}

	return string(bytes.TrimSpace(buf)), nil
}
