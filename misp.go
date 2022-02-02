package misp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

// Client ... XXX
type Client struct {
	BaseURL    *url.URL
	APIKey     string
	VerifyCert bool
}

type InnerEventTag struct {
	ID  string `json:"id"`
	Tag string `json:"tag"`
}

type EventTag struct {
	Event InnerEventTag `json:"Event"`
}

type eventTagResponse struct {
	Saved        bool   `json:"saved"`
	State        string `json:"success"`
	CheckPublish bool   `json:"check_publish"`
}

func NewClient(baseURL string, apiKey string) (Client, error) {
	url, err := url.Parse(baseURL)
	return Client{
		BaseURL:    url,
		APIKey:     apiKey,
		VerifyCert: true,
	}, err
}

func (client *Client) eventTagManagement(path string, eventID string, tag string) (bool, error) {
	req := Request{
		Request: EventTag{
			Event: InnerEventTag{
				ID:  eventID,
				Tag: tag,
			},
		},
	}

	resp, err := client.Post(path, req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var tagResponse eventTagResponse
	d := json.NewDecoder(resp.Body)
	d.Decode(&tagResponse)

	return tagResponse.Saved, err
}

func (client *Client) RemoveEventTag(eventID string, tag string) (bool, error) {
	return client.eventTagManagement("/events/removeTag", eventID, tag)
}

func (client *Client) AddEventTag(eventID string, tag string) (bool, error) {
	return client.eventTagManagement("/events/addTag", eventID, tag)
}

// AddSighting ... XXX
func (client *Client) AddSighting(s *Sighting) (*Response, error) {
	httpResp, err := client.Post("/sightings/add/", Request{Request: s})
	if err != nil {
		return nil, err
	}

	var response Response
	decoder := json.NewDecoder(httpResp.Body)
	if err = decoder.Decode(&response); err != nil {
		return nil, err
	}

	return &response, nil
}

// UploadResponse ... XXX
type UploadResponse struct {
	ID      int      `json:"nononoid"`
	RawID   string   `json:"id"`
	URL     string   `json:"url"`
	Message string   `json:"message"`
	Name    string   `json:"name"`
	Errors  []string `json:"errors"`
}

// UploadSample ... XXX
func (client *Client) UploadSample(sample *SampleUpload) (*UploadResponse, error) {
	req := &Request{Request: sample}

	url := fmt.Sprintf("/events/upload_sample/%s", sample.EventID)
	httpResp, err := client.Post(url, req)
	if err != nil {
		return nil, err
	}

	var resp UploadResponse
	decoder := json.NewDecoder(httpResp.Body)
	if err = decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("Could not unmarshal response: %s", err)
	}

	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("MISP returned an error: %v", resp)
	}

	id, err := strconv.ParseInt(resp.RawID, 10, 32)
	if err != nil {
		return nil, err
	}
	resp.ID = int(id)

	return &resp, nil
}

// DownloadSample downloads a malware sample to the given file
func (client *Client) DownloadSample(sampleID int, filename string) error {
	path := fmt.Sprintf("/attributes/downloadAttachment/download/%d", sampleID)

	httpReq := &http.Request{}
	httpReq.Method = "GET"
	httpReq.URL = client.BaseURL
	httpReq.URL.Path = path

	httpReq.Header = make(http.Header)
	httpReq.Header.Set("Authorization", client.APIKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("Error downloading sample: %s", err.Error())
	}
	defer resp.Body.Close()

	outFile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return fmt.Errorf("Error opening %s: %s", filename, err.Error())
	}

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return fmt.Errorf("Error writing to %s: %s", filename, err.Error())
	}

	return nil
}

// Get is a wrapper to Do()
func (client *Client) Get(path string, req interface{}) (*http.Response, error) {
	return client.Do("GET", path, req)
}

// Post is a wrapper to Do()
func (client *Client) Post(path string, req interface{}) (*http.Response, error) {
	return client.Do("POST", path, req)
}

// AddAttribute adds an attribute to an event
func (client *Client) AddAttribute(eventID string, attr Attribute) (attribute Attribute, err error) {
	var (
		path   string = "/attributes/add/" + eventID
		result map[string]json.RawMessage
	)

	resp, err := client.Post(path, attr)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&result); err != nil {
		return attribute, fmt.Errorf("Could not unmarshal response: %s", err)
	}
	json.Unmarshal(result["Attribute"], &attribute)
	return
}

// Do set the HTTP headers, encode the data in the JSON format and send it to the
// server.
// It checks the HTTP response by looking at the status code and decodes the JSON structure
// to a Response structure.
func (client *Client) Do(method, path string, req interface{}) (*http.Response, error) {
	httpReq := &http.Request{}
	httpTrp := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !client.VerifyCert},
	}

	if req != nil {
		jsonBuf, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq.Body = ioutil.NopCloser(bytes.NewReader(jsonBuf))
	}

	httpReq.Method = method
	httpReq.URL = client.BaseURL
	httpReq.URL.Path = path

	httpReq.Header = make(http.Header)
	httpReq.Header.Set("Authorization", client.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	httpClient := http.Client{
		Transport: httpTrp,
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("MISP server replied status=%d", resp.StatusCode)
	}

	return resp, nil
}
