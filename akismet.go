package akismet

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	AkismetAPIDomain = "rest.akismet.com" // root domain for requests
	Version          = "0.1"              // version of this library
)

var (
	InvalidMethodError = errors.New("Invalid method; method must be GET, POST, PUT, or DELETE")
	EmptyUAError       = errors.New("User Agent must be set.")
	UnknownError       = errors.New("Something weird happened, not 100% sure what.")
)

type AkismetError string // returned for errors from akismet headers

func (a AkismetError) Error() string {
	return string(a)
}

func apiCall(method, endpoint, ua string, body io.Reader) (*http.Response, error) {
	if method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" {
		return nil, InvalidMethodError
	}
	if ua == "" {
		return nil, EmptyUAError
	}
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	return http.DefaultClient.Do(req)
}

// SpamChecker stores the values needed for every request, rather than passing them around all the time.
// ApplicationName is the name of the application using this library; ApplicationVersion is the version
// of the application using this library. Key is your Akismet API key.
type SpamChecker struct {
	Key                string
	ApplicationName    string
	ApplicationVersion string
}

// GetEndpoint returns an API endpoint using the SpamChecker's key.
func (s SpamChecker) GetEndpoint(path string) string {
	path = strings.TrimLeft(path, "/")
	return "https://" + s.Key + "." + AkismetAPIDomain + "/" + path
}

// GetUA returns an appropriate User Agent using the SpamChecker's values.
func (s SpamChecker) GetUA() string {
	return s.ApplicationName + "/" + s.ApplicationVersion + " | dramafever-akismet/" + Version
}

// VerifyKey verifies that the provided key is valid. Site is the main page of the site that is
// making the call, including the protocol. VerifyKey returns true if the key is valid, false if
// it is invalid. If there is an error, it is returned in the string.
func (s SpamChecker) VerifyKey(key, site string) (bool, string) {
	val := make(url.Values)
	val.Set("key", key)
	val.Set("blog", site)
	buf := new(bytes.Buffer)
	buf.WriteString(val.Encode())
	resp, err := apiCall("POST", AkismetAPIDomain+"/1.1/verify-key", s.GetUA(), buf)
	if err != nil {
		return false, "HTTP Error: " + err.Error()
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "Error reading body: " + err.Error()
	}
	if string(b) == "valid" {
		return true, ""
	} else if string(b) == "invalid" || resp.Header.Get("X-akismet-debug-help") != "" {
		return false, resp.Header.Get("X-akismet-debug-help")
	} else {
		return false, "Unknown error."
	}
}

// Comment holds information about and represents a comment that is being checked against Akismet.
type Comment struct {
	UserIP      string // (required) IP address of the comment submitter.
	UserAgent   string // User agent string of the web browser submitting the comment
	Referrer    string // The content of the HTTP_REFERER header should be sent here.
	Permalink   string
	CommentType string // May be blank, comment, trackback, pingback, or a made up value like "registration".
	// see http://blog.akismet.com/2012/06/19/pro-tip-tell-us-your-comment_type/
	CommentAuthor      string    // Name submitted with the comment
	CommentAuthorEmail string    // Email address submitted with the comment
	CommentAuthorURL   string    // URL submitted with comment
	CommentContent     string    // The content that was submitted.
	CommentDate        time.Time // The UTC timestamp of the creation of the comment, in ISO 8601 format.
	// May be omitted if the comment is sent to the API at the time it is created.
	CommentPostModified time.Time // The UTC timestamp of the publication time for the post, page or thread on which the comment was posted.
	SiteLang            string    // Indicates the language(s) in use on the blog or site, in ISO 639-1 format, comma-separated. A site with articles in English and French might use "en, fr_ca".
	SiteCharset         string    // The character encoding for the form values included in comment_* parameters, such as "UTF-8" or "ISO-8859-1".
}

// Values returns a url.Values from a Comment, allowing the Comment to be easily URL-encoded.
func (c Comment) Values() url.Values {
	val := make(url.Values)
	val.Set("user_ip", c.UserIP)
	if c.UserAgent != "" {
		val.Set("user_agent", c.UserAgent)
	}
	if c.Referrer != "" {
		val.Set("referrer", c.Referrer)
	}
	if c.Permalink != "" {
		val.Set("permalink", c.Permalink)
	}
	if c.CommentType != "" {
		val.Set("comment_type", c.CommentType)
	}
	if c.CommentAuthor != "" {
		val.Set("comment_author", c.CommentAuthor)
	}
	if c.CommentAuthorEmail != "" {
		val.Set("comment_author_email", c.CommentAuthorEmail)
	}
	if c.CommentAuthorURL != "" {
		val.Set("comment_author_url", c.CommentAuthorURL)
	}
	if c.CommentContent != "" {
		val.Set("comment_content", c.CommentContent)
	}
	if !c.CommentDate.IsZero() {
		val.Set("comment_date_gmt", c.CommentDate.UTC().Format("2006-01-02T15:04:05Z07:00"))
	}
	if !c.CommentPostModified.IsZero() {
		val.Set("comment_post_modified_gmt", c.CommentPostModified.UTC().Format("2006-01-02T15:04:05Z07:00"))
	}
	if c.SiteLang != "" {
		val.Set("blog_lang", c.SiteLang)
	}
	if c.SiteCharset != "" {
		val.Set("blog_charset", c.SiteCharset)
	}
	return val
}

// CheckComment uses the Akismet API to check if a comment is spam or not. If it returns true,
// the comment is spam. If it returns false, the comment is not. If it returns an error, it may
// be of the AkismetError type, which will hold more information.
func (s SpamChecker) CheckComment(site string, c Comment) (bool, error) {
	val := c.Values()
	val.Set("blog", site)
	buf := new(bytes.Buffer)
	buf.WriteString(val.Encode())
	resp, err := apiCall("POST", s.GetEndpoint("/1.1/comment-check"), s.GetUA(), buf)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if string(b) == "false" {
		return false, nil
	} else if string(b) == "true" {
		return true, nil
	} else if resp.Header.Get("X-akismet-debug-help") != "" {
		return false, AkismetError(resp.Header.Get("X-akismet-debug-help"))
	} else {
		return false, UnknownError
	}
}

// ReportSpam reports a comment that CheckComment decided was not spam as spam.
func (s SpamChecker) ReportSpam(site string, c Comment) error {
	val := c.Values()
	val.Set("blog", site)
	buf := new(bytes.Buffer)
	buf.WriteString(val.Encode())
	resp, err := apiCall("POST", s.GetEndpoint("/1.1/submit-spam"), s.GetUA(), buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ReportHam reports a comment that CheckComment decided was spam as not spam.
func (s SpamChecker) ReportHam(site string, c Comment) error {
	val := c.Values()
	val.Set("blog", site)
	buf := new(bytes.Buffer)
	buf.WriteString(val.Encode())
	resp, err := apiCall("POST", s.GetEndpoint("/1.1/submit-ham"), s.GetUA(), buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
