package misp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type Event struct {
	ID                 string `json:"id"`
	OrgID              string `json:"org_id"`
	Distribution       string `json:"distribution"`
	Info               string `json:"info"`
	OrgcID             string `json:"orgc_id"`
	UUID               string `json:"uuid"`
	Date               string `json:"date"`
	Published          bool   `json:"published"`
	Analysis           string `json:"analysis"`
	AttributeCount     string `json:"attribute_count"`
	Timestamp          string `json:"timestamp"`
	SharingGroupID     string `json:"sharing_group_id"`
	ProposalEmailLock  bool   `json:"proposal_email_lock"`
	Locked             bool   `json:"locked"`
	ThreatLevelID      string `json:"threat_level_id"`
	PublishTimestamp   string `json:"publish_timestamp"`
	SightingTimestamp  string `json:"sighting_timestamp"`
	DisableCorrelation bool   `json:"disable_correlation"`
	ExtendsUUID        string `json:"extends_uuid"`
	EventCreatorEmail  string `json:"event_creator_email"`
	Feed               Feed   `json:"Feed"`
	Org                struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"Org"`
	Orgc struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"Orgc"`
	Attribute       []Attribute       `json:"Attribute"`
	ShadowAttribute []ShadowAttribute `json:"ShadowAttribute"`
	RelatedEvent    []interface{}     `json:"RelatedEvent"`
	Galaxy          []Galaxy          `json:"Galaxy"`
	Object          []Object          `json:"Object"`
	EventReport     []interface{}     `json:"EventReport"`
	Tag             []Tag             `json:"Tag"`
}

func NewEvent() Event {
	now := time.Now()
	y, m, d := now.Date()
	return Event{
		Published:        true,
		UUID:             uuid.NewString(),
		ExtendsUUID:      "",
		Date:             fmt.Sprintf("%04d-%02d-%02d", y, m, d),
		Timestamp:        strconv.FormatInt(now.Unix(), 10),
		PublishTimestamp: strconv.FormatInt(now.Unix(), 10),
		Analysis:         "2",
		ThreatLevelID:    "4",
	}
}

// Get a list of events
func (client *Client) GetEvents() (events []Event, err error) {
	res, err := client.Get("/events", nil)
	if err != nil {
		return
	}

	d := json.NewDecoder(res.Body)
	err = d.Decode(&events)
	return
}

// Get an event from a MISP instance
func (client *Client) GetEvent(id string, deleted bool, extended bool) (event Event, err error) {
	var (
		res      *http.Response
		tmpevent map[string]Event
	)
	data := map[string]bool{}

	if deleted {
		data["deleted"] = true
	}
	if extended {
		data["extended"] = true
	}

	if len(data) > 0 {
		res, err = client.Post("/events/view/"+id, data)
	} else {
		res, err = client.Get("/events/view/"+id, nil)
	}
	if err != nil {
		return
	}

	d := json.NewDecoder(res.Body)
	err = d.Decode(&tmpevent)
	event = tmpevent["Event"]
	return
}

// Check if event exists
func (client *Client) EventExists(id string) (bool, error) {
	if _, err := client.GetEvent(id, false, false); err != nil {
		return false, err
	}
	return true, nil
}

// Add a new event on a MISP instance
func (client *Client) AddEvent(event *Event, metadata bool) (*Response, error) {
	var (
		path string = "/events/add"
		data map[string]*Event
	)

	if metadata {
		path = path + "/metadata:1"
	}
	data["Event"] = event
	_, err := client.Post(path, event)
	return nil, err
}

// Publish the event with one single HTTP POST
func (client *Client) PublishEvent(eventID string, email bool) (*Response, error) {
	var path string
	if email {
		path = "/events/alert/%s"
	} else {
		path = "/events/publish/%s"
	}

	path = fmt.Sprintf(path, eventID)
	_, err := client.Post(path, nil)
	return nil, err
}
