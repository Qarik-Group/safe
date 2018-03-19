package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type X509 struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	Serial      *big.Int
	CRL         *pkix.CertificateList

	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
}

func (s Secret) X509() (*X509, error) {
	if !s.Has("certificate") {
		return nil, fmt.Errorf("not a valid certificate (missing the `certificate` attribute)")
	}
	if !s.Has("key") {
		return nil, fmt.Errorf("not a valid certificate (missing the `key` attribute)")
	}

	v := s.Get("certificate")
	block, rest := pem.Decode([]byte(v))
	if block == nil {
		return nil, fmt.Errorf("not a valid certificate (failed to decode certificate PEM block)")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("contains multiple certificates (is this a bundle?)")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("not a valid certificate (type '%s' != 'CERTIFICATE')", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a valid certificate (%s)", err)
	}

	v = s.Get("key")
	block, rest = pem.Decode([]byte(v))
	if block == nil {
		return nil, fmt.Errorf("not a valid certificate (failed to decode key PEM block)")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("contains multiple keys (what?)")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("not a valid certificate (type '%s' != 'RSA PRIVATE KEY')", block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a valid private key (%s)", err)
	}

	o := &X509{
		Certificate: cert,
		PrivateKey:  key,
		KeyUsage:    cert.KeyUsage,
		ExtKeyUsage: cert.ExtKeyUsage,
	}

	if s.Has("serial") {
		v = s.Get("serial")
		i, err := strconv.ParseInt(v, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("not a valid CA certificate (serial '%s' is malformed)", v)
		}
		o.Serial = big.NewInt(i)
	}

	if s.Has("crl") {
		v = s.Get("crl")
		crl, err := x509.ParseCRL([]byte(v))
		if err != nil {
			return nil, fmt.Errorf("not a valid CA certificate (CRL parsing failed: %s)", err)
		}
		o.CRL = crl
	}

	return o, nil
}

func formatSubject(name pkix.Name) string {
	ss := []string{}
	if name.CommonName != "" {
		ss = append(ss, fmt.Sprintf("cn=%s", name.CommonName))
	}
	for _, s := range name.Country {
		ss = append(ss, fmt.Sprintf("c=%s", s))
	}
	for _, s := range name.Province {
		ss = append(ss, fmt.Sprintf("st=%s", s))
	}
	for _, s := range name.Locality {
		ss = append(ss, fmt.Sprintf("l=%s", s))
	}
	for _, s := range name.Organization {
		ss = append(ss, fmt.Sprintf("o=%s", s))
	}
	for _, s := range name.OrganizationalUnit {
		ss = append(ss, fmt.Sprintf("ou=%s", s))
	}

	return strings.Join(ss, ",")
}

func (x *X509) Subject() string {
	return formatSubject(x.Certificate.Subject)
}

func (x *X509) Issuer() string {
	return formatSubject(x.Certificate.Issuer)
}

func parseSubject(subj string) (pkix.Name, error) {
	/* parse subject names that look like this:
	    /cn=foo.bl/c=us/st=ny/l=buffalo/o=stark & wayne/ou=r&d
	and  CN=foo.bl,C=us,ST=ny,L=buffalo,O=stark & wayne,OU=r&d
	*/

	var (
		pairs []string
		name  pkix.Name
	)

	if subj[0] == '/' {
		pairs = strings.Split(subj[1:], "/")
	} else {
		pairs = strings.Split(subj, ",")
	}

	kvre := regexp.MustCompile(" *= *")
	for _, pair := range pairs {
		kv := kvre.Split(pair, 2)
		if len(kv) != 2 {
			return name, fmt.Errorf("malformed subject component '%s'", pair)
		}
		switch kv[0] {
		case "CN", "cn":
			if name.CommonName != "" {
				return name, fmt.Errorf("multiple common names (CN) found in '%s'", subj)
			}
			name.CommonName = kv[1]
		case "C", "c":
			name.Country = append(name.Country, kv[1])
		case "ST", "st":
			name.Province = append(name.Province, kv[1])
		case "L", "l":
			name.Locality = append(name.Locality, kv[1])
		case "O", "o":
			name.Organization = append(name.Organization, kv[1])
		case "OU", "ou":
			name.OrganizationalUnit = append(name.OrganizationalUnit, kv[1])
		default:
			return name, fmt.Errorf("unrecognized subject component '%s=%s'", kv[0], kv[1])
		}
	}

	return name, nil
}

func categorizeSANs(in []string) (ips []net.IP, domains, emails []string) {
	ips = make([]net.IP, 0)
	domains = make([]string, 0)
	emails = make([]string, 0)

	for _, s := range in {
		ip := net.ParseIP(s)
		if ip != nil {
			ips = append(ips, ip)
			continue
		}

		if strings.Index(s, "@") > 0 {
			emails = append(emails, s)
		} else {
			domains = append(domains, s)
		}
	}

	return
}

var keyUsageLookup = map[string]x509.KeyUsage{
	"digital_signature":  x509.KeyUsageDigitalSignature,
	"non_repudiation":    x509.KeyUsageContentCommitment,
	"content_commitment": x509.KeyUsageContentCommitment,
	"key_encipherment":   x509.KeyUsageKeyEncipherment,
	"data_encipherment":  x509.KeyUsageDataEncipherment,
	"key_agreement":      x509.KeyUsageKeyAgreement,
	"key_cert_sign":      x509.KeyUsageCertSign,
	"crl_sign":           x509.KeyUsageCRLSign,
	"encipher_only":      x509.KeyUsageEncipherOnly,
	"decipher_only":      x509.KeyUsageDecipherOnly,
}

var extendedKeyUsageLookup = map[string]x509.ExtKeyUsage{
	"client_auth":      x509.ExtKeyUsageClientAuth,
	"server_auth":      x509.ExtKeyUsageServerAuth,
	"code_signing":     x509.ExtKeyUsageCodeSigning,
	"email_protection": x509.ExtKeyUsageEmailProtection,
	"timestamping":     x509.ExtKeyUsageTimeStamping,
}

func translateKeyUsage(input []string) (keyUsage x509.KeyUsage, err error) {
	var found bool

	for i, usage := range input {
		var thisKeyUsage x509.KeyUsage
		if thisKeyUsage, found = keyUsageLookup[usage]; !found {
			continue
		}

		input[i] = ""
		keyUsage = keyUsage | thisKeyUsage
	}

	return
}

func translateExtendedKeyUsage(input []string) (extendedKeyUsage []x509.ExtKeyUsage, err error) {
	var found bool

	for _, extUsage := range input {
		var thisExtKeyUsage x509.ExtKeyUsage
		//Was interpreted as a normal key usage
		if extUsage == "" {
			continue
		}

		if thisExtKeyUsage, found = extendedKeyUsageLookup[extUsage]; !found {
			err = fmt.Errorf("%s is not a valid x509 key usage", extUsage)
			break
		}
		extendedKeyUsage = append(extendedKeyUsage, thisExtKeyUsage)
	}
	return
}

func NewCertificate(subj string, names, keyUsage []string, bits int) (*X509, error) {
	if bits != 1024 && bits != 2048 && bits != 4096 {
		return nil, fmt.Errorf("invalid RSA key strength '%d', must be one of: 1024, 2048, 4096", bits)
	}

	name, err := parseSubject(subj)
	if err != nil {
		return nil, err
	}

	ips, domains, emails := categorizeSANs(names)

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	//Hyphens, underscores, spaces, oh my!
	for i, _ := range keyUsage {
		keyUsage[i] = strings.Replace(keyUsage[i], "-", "_", -1)
		keyUsage[i] = strings.Replace(keyUsage[i], " ", "_", -1)
	}

	translatedKeyUsage, err := translateKeyUsage(keyUsage)
	if err != nil {
		return nil, err
	}

	translatedExtKeyUsage, err := translateExtendedKeyUsage(keyUsage)
	if err != nil {
		return nil, err
	}

	return &X509{
		PrivateKey: key,
		Certificate: &x509.Certificate{
			SignatureAlgorithm: x509.SHA512WithRSA, /* FIXME: hard-coded */
			PublicKeyAlgorithm: x509.RSA,
			Subject:            name,
			DNSNames:           domains,
			EmailAddresses:     emails,
			IPAddresses:        ips,
			KeyUsage:           translatedKeyUsage,
			ExtKeyUsage:        translatedExtKeyUsage,
			/* ExtraExtensions */
		},
	}, nil
}

func (x X509) Validate() error {
	if x.Certificate.PublicKeyAlgorithm != x509.RSA {
		return fmt.Errorf("invalid (non-RSA) public key algorithm found in certificate")
	}

	pub := x.Certificate.PublicKey.(*rsa.PublicKey)
	if pub.N.Cmp(x.PrivateKey.N) != 0 {
		return fmt.Errorf("modulus for private key does not match modulus in certificate")
	}
	if pub.E != x.PrivateKey.E {
		return fmt.Errorf("exponent for private key does not match exponent in certificate")
	}

	return nil
}

func (x X509) CheckStrength(bits ...int) error {
	for _, b := range bits {
		if x.PrivateKey.N.BitLen() == b {
			return nil
		}
	}
	return fmt.Errorf("key is a %d-bit RSA key", x.PrivateKey.N.BitLen())
}

func (x X509) IsCA() bool {
	return x.Certificate.IsCA && x.Certificate.BasicConstraintsValid
}

func (x X509) Expired() bool {
	now := time.Now()
	return now.After(x.Certificate.NotAfter) || now.Before(x.Certificate.NotBefore)
}

func (x X509) ValidForIP(ip net.IP) bool {
	for _, valid := range x.Certificate.IPAddresses {
		if valid.Equal(ip) {
			return true
		}
	}
	return false
}

func (x X509) ValidForDomain(domain string) bool {
	for _, valid := range x.Certificate.DNSNames {
		if strings.HasPrefix(valid, "*.") {
			a := strings.Split(valid, ".")
			b := strings.Split(domain, ".")
			for len(a) > 0 && len(b) > 0 && a[0] == "*" {
				a = a[1:]
				b = b[1:]
			}
			if len(a) == 0 || len(b) == 0 || a[0] == "*" {
				return false
			}

			if strings.Join(a, ".") == strings.Join(b, ".") {
				return true
			}
		} else {
			if valid == domain {
				return true
			}
		}
	}
	return false
}

func (x X509) ValidForEmail(email string) bool {
	for _, valid := range x.Certificate.EmailAddresses {
		if valid == email {
			return true
		}
	}
	return false
}

func (x X509) ValidFor(names ...string) (bool, error) {
	ips, domains, emails := categorizeSANs(names)

	for _, ip := range ips {
		if !x.ValidForIP(ip) {
			return false, fmt.Errorf("certificate is not valid for IP '%s'", ip)
		}
	}

	for _, domain := range domains {
		if !x.ValidForDomain(domain) {
			return false, fmt.Errorf("certificate is not valid for DNS domain '%s'", domain)
		}
	}

	for _, email := range emails {
		if !x.ValidForEmail(email) {
			return false, fmt.Errorf("certificate is not valid for email address '%s'", email)
		}
	}

	return true, nil
}

func (x *X509) MakeCA(serial int64) {
	x.Certificate.BasicConstraintsValid = true
	x.Certificate.IsCA = true
	x.Certificate.MaxPathLen = 1
	x.Serial = big.NewInt(serial)
	x.CRL = &pkix.CertificateList{}
	x.CRL.TBSCertList.RevokedCertificates = make([]pkix.RevokedCertificate, 0)
}

func (x X509) Secret(skipIfExists bool) (*Secret, error) {
	s := NewSecret()

	cert := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x.Certificate.Raw,
	}))
	key := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(x.PrivateKey),
	}))

	err := s.Set("certificate", cert, skipIfExists)
	if err != nil {
		return s, err
	}
	err = s.Set("key", key, skipIfExists)
	if err != nil {
		return s, err
	}
	err = s.Set("combined", cert+key, skipIfExists)
	if err != nil {
		return s, err
	}

	if x.IsCA() {
		err = s.Set("serial", x.Serial.Text(16), skipIfExists)
		if err != nil {
			return s, err
		}

		b, err := x.Certificate.CreateCRL(rand.Reader, x.PrivateKey, x.CRL.TBSCertList.RevokedCertificates, time.Now(), time.Now().Add(10*365*24*time.Hour))
		if err != nil {
			return s, err
		}
		err = s.Set("crl", string(pem.EncodeToMemory(&pem.Block{
			Type:  "X509 CRL",
			Bytes: b,
		})), skipIfExists)
		if err != nil {
			return s, err
		}
	}

	return s, nil
}

func (ca *X509) Sign(x *X509, ttl time.Duration) error {
	if ca.Serial == nil {
		x.Certificate.SerialNumber = big.NewInt(1)
	} else {
		x.Certificate.SerialNumber = ca.Serial
		ca.Serial.Add(ca.Serial, big.NewInt(1))
	}

	x.Certificate.NotBefore = time.Now()
	x.Certificate.NotAfter = time.Now().Add(ttl)
	raw, err := x509.CreateCertificate(rand.Reader, x.Certificate, ca.Certificate, x.PrivateKey.Public(), ca.PrivateKey)
	if err != nil {
		return err
	}
	x.Certificate.Raw = raw
	return nil
}

func (ca *X509) Revoke(cert *X509) {
	if ca.HasRevoked(cert) {
		return
	}

	ca.CRL.TBSCertList.RevokedCertificates = append(ca.CRL.TBSCertList.RevokedCertificates, pkix.RevokedCertificate{
		SerialNumber:   cert.Certificate.SerialNumber,
		RevocationTime: time.Now(),
	})
}

func (ca *X509) HasRevoked(cert *X509) bool {
	for _, rvk := range ca.CRL.TBSCertList.RevokedCertificates {
		if rvk.SerialNumber.Cmp(cert.Certificate.SerialNumber) == 0 {
			return true
		}
	}
	return false
}
