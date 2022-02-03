package misp

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Sighting ... XXX
type Sighting struct {
	ID        string   `json:"id,omitempty"`
	UUID      string   `json:"uuid,omitempty"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
	Timestamp int      `json:"timestamp,omitempty"`
}

// Request ... XXX
type Request struct {
	Request interface{} `json:"request"`
}

// SampleFile ... XXX
type SampleFile struct {
	Filename string `json:"filename,omitempty"`
	Data     string `json:"data,omitempty"`
}

// SampleUpload ... XXX
type SampleUpload struct {
	Files        []SampleFile `json:"files,omitempty"`
	Distribution string       `json:"distribution,omitempty"`
	Comment      string       `json:"comment,omitempty"` // comment field of any attribute created
	EventID      string       `json:"event_id,omitempty"`
	ToIDS        bool         `json:"to_ids,omitempty"`
	Category     string       `json:"category,omitempty"`
	Info         string       `json:"info,omitempty"` // event info field if no event ID supplied
}

// XResponse ... XXX
type XResponse struct {
	Name    string `json:"name,omitempty"`
	Message string `json:"message,omitempty"`
	URL     string `json:"url,omitempty"`
	Errors  string `json:"errors,omitempty"`
	ID      int    `json:"id,omitempty"`
}

// Response is the outer layer of each MISP response
type Response struct {
}

type searchOuterResponse struct {
	// Response can be an empty array or an object
	Response json.RawMessage `json:"response"`
}

type searchInnerResponse struct {
	Attribute []Attribute `json:"Attribute,omitempty"`
}

type Attribute struct {
	ID                 string `json:"id"`
	EventID            string `json:"event_id"`
	ObjectID           string `json:"object_id"`
	ObjectRelation     string `json:"object_relation"`
	Category           string `json:"category"`
	Type               string `json:"type"`
	Value              string `json:"value"`
	ToIDS              bool   `json:"to_ids"`
	UUID               string `json:"uuid"`
	Timestamp          string `json:"timestamp"`
	Distribution       string `json:"distribution"`
	SharingGroupID     string `json:"sharing_group_id"`
	Comment            string `json:"comment"`
	Deleted            bool   `json:"deleted"`
	DisableCorrelation bool   `json:"disable_correlation"`
	FirstSeen          string `json:"first_seen"`
	LastSeen           string `json:"last_seen"`
}

func NewAttribute() Attribute {
	return Attribute{
		Comment:   "",
		UUID:      uuid.NewString(),
		Timestamp: strconv.FormatInt(time.Now().Unix(), 10),
	}
}

type ShadowAttribute struct {
	ID                 string `json:"id"`
	EventID            string `json:"event_id"`
	ObjectID           string `json:"object_id"`
	ObjectRelation     string `json:"object_relation"`
	Category           string `json:"category"`
	Type               string `json:"type"`
	Value              string `json:"value"`
	ToIds              bool   `json:"to_ids"`
	UUID               string `json:"uuid"`
	Timestamp          string `json:"timestamp"`
	Distribution       string `json:"distribution"`
	SharingGroupID     string `json:"sharing_group_id"`
	Comment            string `json:"comment"`
	Deleted            bool   `json:"deleted"`
	DisableCorrelation bool   `json:"disable_correlation"`
	FirstSeen          string `json:"first_seen"`
	LastSeen           string `json:"last_seen"`
}

type Galaxy struct {
	ID             string `json:"id"`
	UUID           string `json:"uuid"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Description    string `json:"description"`
	Version        string `json:"version"`
	Icon           string `json:"icon"`
	Namespace      string `json:"namespace"`
	KillChainOrder struct {
		FraudTactics []string `json:"fraud-tactics"`
	} `json:"kill_chain_order"`
}

type Object struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	MetaCategory    string      `json:"meta-category"`
	Description     string      `json:"description"`
	TemplateUUID    string      `json:"template_uuid"`
	TemplateVersion string      `json:"template_version"`
	EventID         string      `json:"event_id"`
	UUID            string      `json:"uuid"`
	Timestamp       string      `json:"timestamp"`
	Distribution    string      `json:"distribution"`
	SharingGroupID  string      `json:"sharing_group_id"`
	Comment         string      `json:"comment"`
	Deleted         bool        `json:"deleted"`
	FirstSeen       string      `json:"first_seen"`
	LastSeen        string      `json:"last_seen"`
	Attribute       []Attribute `json:"Attribute"`
}

type Tag struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Colour         string `json:"colour"`
	Exportable     bool   `json:"exportable"`
	OrgID          string `json:"org_id"`
	UserID         string `json:"user_id"`
	HideTag        bool   `json:"hide_tag"`
	NumericalValue string `json:"numerical_value"`
	IsGalaxy       bool   `json:"is_galaxy"`
	IsCustomGalaxy bool   `json:"is_custom_galaxy"`
	Inherited      int    `json:"inherited"`
}

type Feed struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Provider        string `json:"provider"`
	URL             string `json:"url"`
	Rules           string `json:"rules"`
	Enabled         bool   `json:"enabled"`
	Distribution    string `json:"distribution"`
	SharingGroupID  string `json:"sharing_group_id"`
	TagID           string `json:"tag_id"`
	Default         bool   `json:"default"`
	SourceFormat    string `json:"source_format"`
	FixedEvent      bool   `json:"fixed_event"`
	DeltaMerge      bool   `json:"delta_merge"`
	EventID         string `json:"event_id"`
	Publish         bool   `json:"publish"`
	OverrideIds     bool   `json:"override_ids"`
	Settings        string `json:"settings"`
	InputSource     string `json:"input_source"`
	DeleteLocalFile bool   `json:"delete_local_file"`
	LookupVisible   bool   `json:"lookup_visible"`
	Headers         string `json:"headers"`
	CachingEnabled  bool   `json:"caching_enabled"`
	ForceToIds      bool   `json:"force_to_ids"`
	OrgcID          string `json:"orgc_id"`
	CacheTimestamp  string `json:"cache_timestamp"`
}

func ToMap(src interface{}) (r map[string]interface{}, err error) {
	b, err := json.Marshal(src)
	if err != nil {
		return
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return
	}
	return
}
