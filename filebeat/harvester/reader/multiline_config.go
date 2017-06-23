package reader

import (
	"fmt"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/match"
)

type MultilineConfig struct {
	Provider     string         `config:"provider"`
	Negate       bool           `config:"negate"`
	Match        string         `config:"match"`
	MaxLines     *int           `config:"max_lines"`
	Pattern      *match.Matcher `config:"pattern"`
	Timeout      *time.Duration `config:"timeout" validate:"positive"`
	FlushPattern *match.Matcher `config:"flush_pattern"`
	Kubernetes   *common.Config `config:"kubernetes"`
	Docker       *common.Config `config:"docker"`
}

// Kubernetes config to get pattern and other config from pod annotations
type KubernetesConfig struct {
	InCluster         bool   `config:"in_cluster"`
	KubeConfig        string `config:"kube_config"`
	Host              string `config:"host"`
	Namespace         string `config:"namespace"`
	PatternAnnotation string `config:"pattern_annotation"`
	MatcherAnnotation string `config:"match_annotation"`
	NegateAnnotation  string `config:"negate_annotation"`
}

// Docker config to get pattern and other config from container labels
type DockerConfig struct {
	Host         string     `config:"host"`
	TLS          *TLSConfig `config:"ssl"`
	LogsPath     string     `config:"logs_path"`
	PatternLabel string     `config:"pattern_label"`
	MatcherLabel string     `config:"match_label"`
	NegateLabel  string     `config:"negate_label"`
}

// TLSConfig for docker socket connection
type TLSConfig struct {
	CA          string `config:"certificate_authority"`
	Certificate string `config:"certificate"`
	Key         string `config:"key"`
}

func (c *MultilineConfig) Validate() error {

	provider := c.Provider
	if provider == "" || provider != "Default" {
		return nil
	}
	if c.Match != "after" && c.Match != "before" {
		return fmt.Errorf("unknown matcher type: %s", c.Match)
	}
	return nil
}

func defaultDockerConfig() DockerConfig {
	return DockerConfig{
		Host:         "unix:///var/run/docker.sock",
		LogsPath:     "/var/lib/docker/containers",
		PatternLabel: "filebeat.multiline.pattern",
		MatcherLabel: "filebeat.multiline.match",
		NegateLabel:  "filebeat.multiline.negate",
	}
}

func defaultKubernetesConfig() KubernetesConfig {
	return KubernetesConfig{
		InCluster:         true,
		PatternAnnotation: "filebeat.multiline.pattern",
		MatcherAnnotation: "filebeat.multiline.match",
		NegateAnnotation:  "filebeat.multiline.negate",
	}
}
