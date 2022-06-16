package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

func main() {

	opt := GenerateOptions{
		Department: "IT",
		Email:      "it@xxx.com",
		Secret:     "EELXMGPKYZAQ26JVLWOB2U2ZJTZCW72X",
	}
	url, err := GenerateUrl(opt)
	if err != nil {
		panic(err)
	}
	fmt.Println(url)
	validateCode()
}

func GenerateCode(counter uint64) (string, error) {

	secret := "EELXMGPKYZAQ26JVLWOB2U2ZJTZCW72X"
	secret = strings.ToUpper(secret)
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 8)
	mac := hmac.New(sha1.New, secretBytes)
	binary.BigEndian.PutUint64(buf, counter)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf

	val := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	mod := int32(val % int64(math.Pow10(6)))
	f := fmt.Sprintf("%%0%dd", 6)
	return fmt.Sprintf(f, mod), nil
}

func validateCode() {
	counters := []uint64{}
	counter := int64(math.Floor(float64(time.Now().UTC().Unix()) / float64(30)))

	counters = append(counters, uint64(counter))

	counters = append(counters, uint64(counter+int64(1)))
	counters = append(counters, uint64(counter-int64(1)))

	for _, counter := range counters {
		ValidateCustom(counter)
	}

}

type ValidateOpts struct {
	Digits    int
	Algorithm string
}

func ValidateCustom(counter uint64) {

	code, err := GenerateCode(counter)
	fmt.Println(code)
	if err != nil {
		panic(err)
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte("975882")) == 1 {
		fmt.Println("========")
	}
}

type GenerateOptions struct {
	Department string
	Email      string
	Secret     string
}

func GenerateUrl(opts GenerateOptions) (string, error) {
	v := url.Values{}

	if len(opts.Secret) != 0 {
		v.Set("secret", opts.Secret)
	} else {
		return "", errors.New("secret is not exist")
	}
	v.Set("issuer", opts.Department)
	v.Set("period", "30")
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + opts.Department + ":" + opts.Email,
		RawQuery: v.Encode(),
	}

	return u.String(), nil
}
