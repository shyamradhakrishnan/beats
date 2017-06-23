// +build !integration

package reader

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/elastic/beats/filebeat/harvester/encoding"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/match"
	"github.com/stretchr/testify/assert"
)

type bufferSource struct{ buf *bytes.Buffer }

func (p bufferSource) Read(b []byte) (int, error) { return p.buf.Read(b) }
func (p bufferSource) Close() error               { return nil }
func (p bufferSource) Name() string               { return "buffer" }
func (p bufferSource) Stat() (os.FileInfo, error) { return nil, errors.New("unknown") }
func (p bufferSource) Continuable() bool          { return false }

func TestMultilineAfterOK(t *testing.T) {
	pattern := match.MustCompile(`^[ \t] +`) // next line is indented by spaces
	testMultilineOK(t,
		MultilineConfig{
			Pattern: &pattern,
			Match:   "after",
		},
		2,
		"line1\n  line1.1\n  line1.2\n",
		"line2\n  line2.1\n  line2.2\n",
	)
}

func TestMultilineBeforeOK(t *testing.T) {
	pattern := match.MustCompile(`\\$`) // previous line ends with \

	testMultilineOK(t,
		MultilineConfig{
			Pattern: &pattern,
			Match:   "before",
		},
		2,
		"line1 \\\nline1.1 \\\nline1.2\n",
		"line2 \\\nline2.1 \\\nline2.2\n",
	)
}

func TestMultilineAfterNegateOK(t *testing.T) {
	pattern := match.MustCompile(`^-`) // first line starts with '-' at beginning of line

	testMultilineOK(t,
		MultilineConfig{
			Pattern: &pattern,
			Negate:  true,
			Match:   "after",
		},
		2,
		"-line1\n  - line1.1\n  - line1.2\n",
		"-line2\n  - line2.1\n  - line2.2\n",
	)
}

func TestMultilineBeforeNegateOK(t *testing.T) {
	pattern := match.MustCompile(`;$`) // last line ends with ';'

	testMultilineOK(t,
		MultilineConfig{
			Pattern: &pattern,
			Negate:  true,
			Match:   "before",
		},
		2,
		"line1\nline1.1\nline1.2;\n",
		"line2\nline2.1\nline2.2;\n",
	)
}

func TestMultilineAfterNegateOKFlushPattern(t *testing.T) {
	flushMatcher := match.MustCompile(`EventEnd`)
	pattern := match.MustCompile(`EventStart`)

	testMultilineOK(t,
		MultilineConfig{
			Pattern:      &pattern,
			Negate:       true,
			Match:        "after",
			FlushPattern: &flushMatcher,
		},
		3,
		"EventStart\nEventId: 1\nEventEnd\n",
		"OtherThingInBetween\n", // this should be a seperate event..
		"EventStart\nEventId: 2\nEventEnd\n",
	)
}

func TestMultilineAfterNegateOKFlushPatternWhereTheFirstLinesDosentMatchTheStartPattern(t *testing.T) {
	flushMatcher := match.MustCompile(`EventEnd`)
	pattern := match.MustCompile(`EventStart`)

	testMultilineOK(t,
		MultilineConfig{
			Pattern:      &pattern,
			Negate:       true,
			Match:        "after",
			FlushPattern: &flushMatcher,
		},
		3, //first two non-matching lines, will be merged to one event
		"StartLineThatDosentMatchTheEvent\nOtherThingInBetween\n",
		"EventStart\nEventId: 2\nEventEnd\n",
		"EventStart\nEventId: 3\nEventEnd\n",
	)
}

func TestMultilineBeforeNegateOKWithEmptyLine(t *testing.T) {
	pattern := match.MustCompile(`;$`) // last line ends with ';'
	testMultilineOK(t,
		MultilineConfig{
			Pattern: &pattern,
			Negate:  true,
			Match:   "before",
		},
		2,
		"line1\n\n\nline1.2;\n",
		"line2\nline2.1\nline2.2;\n",
	)
}

func TestDefaultKubeProviderConfig(t *testing.T) {
	config := MultilineConfig{
		Negate: true,
		Match:  "after",
	}
	defaultConfig := defaultKubernetesConfig()
	kubeConfig := config.Kubernetes
	if kubeConfig == nil {
		kubeConfig = common.NewConfig()
	}
	err := kubeConfig.Unpack(&defaultConfig)
	assert.NoError(t, err, "Error occured while creating multi-line config")

	assert.Equal(t, true, defaultConfig.InCluster,
		"The default value of InCluster must be true")
	assert.Equal(t, "filebeat.multiline.pattern", defaultConfig.PatternAnnotation,
		"The default value of pattern did not match")
	assert.Equal(t, "filebeat.multiline.negate", defaultConfig.NegateAnnotation,
		"The default value of negate did not match")
	assert.Equal(t, "filebeat.multiline.matcher", defaultConfig.MatcherAnnotation,
		"The default value of matcher did not match")
}

func TestDefaultDockerProviderConfig(t *testing.T) {
	config := MultilineConfig{
		Negate: true,
		Match:  "after",
	}
	defaultConfig := defaultDockerConfig()
	dockerConfig := config.Docker
	if dockerConfig == nil {
		dockerConfig = common.NewConfig()
	}
	err := dockerConfig.Unpack(&defaultConfig)
	assert.NoError(t, err, "Error occured while creating multi-line config")

	assert.Equal(t, "unix:///var/run/docker.sock", defaultConfig.Host,
		"The default value of InCluster must be true")
	assert.Equal(t, "filebeat.multiline.pattern", defaultConfig.PatternLabel,
		"The default value of pattern did not match")
	assert.Equal(t, "filebeat.multiline.negate", defaultConfig.NegateLabel,
		"The default value of negate did not match")
	assert.Equal(t, "filebeat.multiline.matcher", defaultConfig.MatcherLabel,
		"The default value of matcher did not match")
}

func TestInvalidProvider(t *testing.T) {
	config := MultilineConfig{
		Provider: "Invalid",
	}
	_, err := instantiateProvider(&config, "")
	assert.Error(t, err, "Error occured while creating multi-line config")
}

func TestDefaultProvider(t *testing.T) {
	pattern := match.MustCompile(`;$`)
	config := MultilineConfig{
		Pattern: &pattern,
		Negate:  true,
		Match:   "before",
	}
	provider, err := instantiateProvider(&config, "")
	assert.NoError(t, err, "Since no provider was defined, the default should be user")
	assert.Equal(t, true, provider.negate,
		"Wrong value for negate from default provider")
	assert.Equal(t, "before", provider.match,
		"Wrong value for match from default provider")
	assert.Equal(t, pattern, provider.pattern,
		"Wrong value for pattern from default provider")

}

func TestDockerProviderFromSource(t *testing.T) {
	getContainerJsonFromContainerId = func(dockerConfig *DockerConfig, cid string) (*types.ContainerJSON, error) {
		return  &types.ContainerJSON{
			Config:&container.Config{
				Labels:map[string]string{
					"filebeat.multiline.pattern": "pattern",
					"filebeat.multiline.negate": "true",
					"filebeat.multiline.match": "after",
				},
			},
		}, nil
	}
	config := MultilineConfig{
		Provider: "Docker",
	}

	source := "/var/lib/docker/containers/bfd50dda2b75462da051e969b1700867837fc2866873ad4aea24973d75fba875/json.log"
	provider, err := createDockerProvider(&config, source)

	assert.NoError(t, err, "The docker container json was not retrieved successfully")

	assert.Equal(t, true, provider.negate,
		"Wrong value for negate from container label")
	assert.Equal(t, "after", provider.match,
		"Wrong value for match from  container label")
	assert.Equal(t,  match.MustCompile("pattern"), provider.pattern,
		"Wrong value for pattern from  container label")
}

func TestReturnErrorIfSourceCouldNotBeMatched(t *testing.T) {
	getContainerJsonFromContainerId = func(dockerConfig *DockerConfig, cid string) (*types.ContainerJSON, error) {
		return  &types.ContainerJSON{}, nil
	}
	config := MultilineConfig{
		Provider: "Docker",
	}

	source := "/containers/bfd50dda2b75462da051e969b1700867837fc2866873ad4aea24973d75fba875/json.log"
	_, err := createDockerProvider(&config, source)

	assert.Error(t, err, "The docker container id could not be parsed from source")
}

func TestReturnDefaultMultilinePatternOnMissingInfo(t *testing.T) {
	getContainerJsonFromContainerId = func(dockerConfig *DockerConfig, cid string) (*types.ContainerJSON, error) {
		return  &types.ContainerJSON{
			Config:&container.Config{
				Labels:map[string]string{
					"filebeat.multiline.pattern": "pattern",
				},
			},
		}, nil
	}
	multilineConfig := MultilineConfig{
		Provider: "Docker",
	}
	source := "/var/lib/docker/containers/bfd50dda2b75462da051e969b1700867837fc2866873ad4aea24973d75fba875/json.log"
	provider, err := createDockerProvider(&multilineConfig, source)

	assert.NoError(t, err, "If metadata is missing, default patterns must be used")

	assert.Equal(t,  match.MustCompile("^[.*]"), provider.pattern,
		"The default pattern was not returned")
}

func TestKubernetesProviderFromSource(t *testing.T) {
	getContainerJsonFromContainerId = func(dockerConfig *DockerConfig, cid string) (*types.ContainerJSON, error) {
		return  &types.ContainerJSON{
			Config:&container.Config{
				Labels:map[string]string{
					"io.kubernetes.pod.name": "podname",
					"io.kubernetes.pod.namespace": "namespace",
				},
			},
		}, nil
	}
	getKubernetesPod = func(kubernetesConfig KubernetesConfig, podName string, podNameSpace string) (map[string]string, error) {
		return map[string]string{
			"filebeat.multiline.pattern": "pattern",
			"filebeat.multiline.negate": "true",
			"filebeat.multiline.match": "after",
		}, nil
	}
	config := MultilineConfig{
		Provider: "Kubernetes",
	}

	source := "/var/lib/docker/containers/bfd50dda2b75462da051e969b1700867837fc2866873ad4aea24973d75fba875/json.log"
	provider, err := createKubernetesProvider(&config, source)

	assert.NoError(t, err, "The docker container json was not retrieved successfully")

	assert.Equal(t, true, provider.negate,
		"Wrong value for negate from container label")
	assert.Equal(t, "after", provider.match,
		"Wrong value for match from  container label")
	assert.Equal(t,  match.MustCompile("pattern"), provider.pattern,
		"Wrong value for pattern from  container label")
}

func testMultilineOK(t *testing.T, cfg MultilineConfig, events int, expected ...string) {
	_, buf := createLineBuffer(expected...)
	reader := createMultilineTestReader(t, buf, cfg)

	var messages []Message
	for {
		message, err := reader.Next()
		if err != nil {
			break
		}

		messages = append(messages, message)
	}

	if len(messages) != events {
		t.Fatalf("expected %v lines, read only %v line(s)", len(expected), len(messages))
	}

	for i, message := range messages {
		var tsZero time.Time

		assert.NotEqual(t, tsZero, message.Ts)
		assert.Equal(t, strings.TrimRight(expected[i], "\r\n "), string(message.Content))
		assert.Equal(t, len(expected[i]), int(message.Bytes))
	}
}

func createMultilineTestReader(t *testing.T, in *bytes.Buffer, cfg MultilineConfig) Reader {
	encFactory, ok := encoding.FindEncoding("plain")
	if !ok {
		t.Fatalf("unable to find 'plain' encoding")
	}

	enc, err := encFactory(in)
	if err != nil {
		t.Fatalf("failed to initialize encoding: %v", err)
	}

	var reader Reader
	reader, err = NewEncode(in, enc, 4096)
	if err != nil {
		t.Fatalf("Failed to initialize line reader: %v", err)
	}

	reader, err = NewMultiline(NewStripNewline(reader), "\n", 1<<20, &cfg, "")
	if err != nil {
		t.Fatalf("failed to initializ reader: %v", err)
	}

	return reader
}

func createLineBuffer(lines ...string) ([]string, *bytes.Buffer) {
	buf := bytes.NewBuffer(nil)
	for _, line := range lines {
		buf.WriteString(line)
	}
	return lines, buf
}
