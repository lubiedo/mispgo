package misp

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Search struct {
	Page                   int      `json:"page"`
	Limit                  int      `json:"limit"`
	Value                  string   `json:"value"`
	Type                   string   `json:"type"`
	Category               string   `json:"category"`
	Org                    string   `json:"org"`
	Tags                   []string `json:"tags"`
	SearchAll              string   `json:"searchall"`
	From                   string   `json:"from"`
	To                     string   `json:"to"`
	Last                   int      `json:"last"`
	EventID                string   `json:"eventid"`
	WithAttachments        bool     `json:"withAttachments"`
	Metadata               bool     `json:"metadata"`
	UUID                   string   `json:"uuid"`
	PublishTimestamp       string   `json:"publish_timestamp"`
	Published              bool     `json:"published"`
	Timestamp              string   `json:"timestamp"`
	AttributeTimestamp     string   `json:"attribute_timestamp"`
	EnforceWarningList     bool     `json:"enforceWarninglist"`
	ToIDS                  bool     `json:"to_ids"`
	Deleted                bool     `json:"deleted"`
	EventTimestamp         string   `json:"event_timestamp"`
	ThreatLevelID          string   `json:"threat_level_id"`
	EventInfo              string   `json:"eventinfo"`
	DecayingModel          string   `json:"decayingModel"`
	Score                  string   `json:"score"`
	FirstSeen              string   `json:"first_seen"`
	LastSeen               string   `json:"last_seen"`
	IncludeEventUUID       bool     `json:"includeEventUuid"`
	IncludeEventTags       bool     `json:"includeEventTags"`
	IncludeProposals       bool     `json:"includeProposals"`
	RequestedAttributes    []string `json:"requested_attributes"`
	IncludeContext         bool     `json:"includeContext"`
	Headerless             bool     `json:"headerless"`
	IncludeWarningListHits bool     `json:"includeWarninglistHits"`
	AttackGalaxy           string   `json:"attackGalaxy"`
	ObjectRelation         string   `json:"object_relation"`
	IncludeSightings       bool     `json:"includeSightings"`
	IncludeCorrelations    bool     `json:"includeCorrelations"`
	ModelOverrides         struct {
		Lifetime         int         `json:"lifetime"`
		DecaySpeed       float64     `json:"decay_speed"`
		Threshold        int         `json:"threshold"`
		DefaultBaseScore int         `json:"default_base_score"`
		BaseScoreConfig  interface{} `json:"base_score_config"`
	} `json:"modelOverrides"`
	IncludeDecayScore bool   `json:"includeDecayScore"`
	IncludeFullModel  bool   `json:"includeFullModel"`
	ExcludeDecayed    bool   `json:"excludeDecayed"`
	ReturnFormat      string `json:"returnFormat"`
	SgReferenceOnly   bool   `json:"sgReferenceOnly"`
	ExcludeLocalTags  bool   `json:"excludeLocalTags"`
	Date              string `json:"date"`
	IncludeSightingDB bool   `json:"includeSightingdb"`
	Tag               string `json:"tag"`
}

type IndexSearch struct {
	Page             int      `json:"page,omitempty"`
	Limit            int      `json:"limit,omitempty"`
	Sort             string   `json:"sort,omitempty"`
	Direction        string   `json:"direction,omitempty"`
	Minimal          bool     `json:"minimal,omitempty"`
	Attribute        string   `json:"attribute,omitempty"`
	EventID          string   `json:"eventid,omitempty"`
	DateFrom         string   `json:"datefrom,omitempty"`
	DateUntil        string   `json:"dateuntil,omitempty"`
	Org              string   `json:"org,omitempty"`
	EventInfo        string   `json:"eventinfo,omitempty"`
	Tag              string   `json:"tag,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Distribution     string   `json:"distribution,omitempty"`
	SharingGroup     string   `json:"sharinggroup,omitempty"`
	Analysis         string   `json:"analysis,omitempty"`
	ThreatLevel      string   `json:"threatlevel,omitempty"`
	Email            string   `json:"email,omitempty"`
	HasProposal      string   `json:"hasproposal,omitempty"`
	Timestamp        string   `json:"timestamp,omitempty"`
	PublishTimestamp string   `json:"publish_timestamp,omitempty"`
	SearchDateFrom   string   `json:"searchDatefrom,omitempty"`
	SearchDateUntil  string   `json:"searchDateuntil,omitempty"`
}

type SearchEventsResult struct {
	Response []map[string]Event `json:"response"`
}

type SearchAttributesResult struct {
	Response map[string][]Attribute `json:"response"`
}

// Search events, attributes or objects in the MISP instance
func (client *Client) Search(controller string, search *Search) (result []byte, err error) {
	var (
		path        string
		controllers []string = []string{
			"events", "attributes", "objects",
		}
		invalid_controller bool = true
	)

	for _, c := range controllers {
		if strings.Compare(controller, c) == 0 {
			invalid_controller = false
		}
	}
	if invalid_controller {
		return result, fmt.Errorf("Search(): Invalid controller")
	}
	path = fmt.Sprintf("/%s/restSearch", controller)

	res, err := client.Post(path, search)
	if err != nil {
		return
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}

func (client *Client) SearchEvents(search *Search) (events SearchEventsResult, err error) {
	if data, err := client.Search("events", search); err == nil {
		err = json.Unmarshal(data, &events)
	}
	return
}

func (client *Client) SearchAttributes(search *Search) (attributes SearchAttributesResult, err error) {
	if data, err := client.Search("attributes", search); err == nil {
		err = json.Unmarshal(data, &attributes)
	}
	return
}

// Search event metadata shown on the event index page
func (client *Client) SearchIndex(search *IndexSearch) (result []Event, err error) {
	res, err := client.Post("/events/index", *search)
	if err != nil {
		return
	}
	defer res.Body.Close()
	d := json.NewDecoder(res.Body)
	err = d.Decode(&result)
	return
}
