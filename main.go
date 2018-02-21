package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type Params struct {
	ApplicationID string `json:"application_id"`
	AuthKey       string `json:"auth_key"`
	Timestamp     int    `json:"timestamp"`
	Nonce         int    `json:"nonce"`
	Signature     string `json:"signature"`
	User          `json:"user"`
}

type User struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type Config struct {
	ServerURL string `yaml:"server_url"`
	AppID     string `yaml:"app_id"`
	AuthKey   string `yaml:"auth_key"`
	SecretKey string `yaml:"secr_key"`
	Login     string `yaml:"login"`
	Password  string `yaml:"password"`
}

func main() {
	var configFile string

	flag.StringVar(&configFile, "C", "", "Configuration file path.")
	flag.Usage = Usage
	flag.Parse()

	var currentConfig Config
	ParseConfig(configFile, &currentConfig)
	fmt.Println(currentConfig)

	paramsReq := &Params{
		ApplicationID: currentConfig.AppID,
		AuthKey:       currentConfig.AuthKey,
		Timestamp:     int(time.Now().Unix()),
		Nonce:         rand.Intn(9999999999),
		Signature:     "",
		User: User{
			Login:    currentConfig.Login,
			Password: currentConfig.Password,
		},
	}

	paramsReq.Signature = GenSignature(paramsReq, currentConfig.SecretKey)
	jsonParamsReq, _ := json.Marshal(paramsReq)

	response := CreateSession(currentConfig.ServerURL, jsonParamsReq)
	fmt.Println("response Body:", string(response))
}

// ParseConfig slould parse provided config file
func ParseConfig(config string, authParams *Config) {
	filename, _ := filepath.Abs(config)
	yamlFile, err := ioutil.ReadFile(filename)

	err = yaml.Unmarshal(yamlFile, &authParams)
	if err != nil {
		panic(err)
	}
}

// GenSignature makes signature from session params
func GenSignature(paramsReq *Params, secretKey string) string {
	signStrEnc := url.Values{}
	signStrEnc.Add("application_id", paramsReq.ApplicationID)
	signStrEnc.Add("auth_key", paramsReq.AuthKey)
	signStrEnc.Add("nonce", strconv.Itoa(paramsReq.Nonce))
	signStrEnc.Add("timestamp", strconv.Itoa(paramsReq.Timestamp))
	signStrEnc.Add("user[login]", paramsReq.Login)
	signStrEnc.Add("user[password]", paramsReq.Password)

	signStr := signStrEnc.Encode()
	signStr = strings.Replace(signStr, "%5B", "[", -1)
	signStr = strings.Replace(signStr, "%5D", "]", -1)

	hash := hmac.New(sha1.New, []byte(secretKey))
	hash.Write([]byte(signStr))

	return hex.EncodeToString(hash.Sum(nil))
}

// CreateSession makes http request on /session.json
func CreateSession(serverURL string, json []byte) []byte {
	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(json))
	req.Header.Set("QuickBlox-REST-API-Version", "0.1.0")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	body, _ := ioutil.ReadAll(resp.Body)

	return body
}

// Usage will print out the flag options for the server.
func Usage() {
	fmt.Println("-C Config file (yml)")
	os.Exit(0)
}
