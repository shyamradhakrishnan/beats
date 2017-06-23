package reader

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/match"
	"github.com/ericchiang/k8s"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
)

// Select Docker API version
const dockerAPIVersion = "1.22"

type MultilineConfigProvider struct {
	pattern match.Matcher
	negate  bool
	match   string
}


func instantiateProvider(multilineConfig *MultilineConfig, containerId string) (MultilineConfigProvider, error) {
	provider := multilineConfig.Provider

	if provider == "" {
		provider = "Default"
	}

	types := map[string]func(*MultilineConfig, string) (MultilineConfigProvider, error){
		"Default":    createDefaultProvider,
		"Kubernetes": createKubernetesProvider,
		"Docker":     createDockerProvider,
	}

	constructor, ok := types[provider]

	if !ok {
		return defaultMultilineConfigProvider(), errors.New("The multiline provider in the configuration is not valid")
	}

	return constructor(multilineConfig, containerId)
}

func createKubernetesProvider(multilineConfig *MultilineConfig, source string) (MultilineConfigProvider, error) {
	config, err := getKubernetesConfig(multilineConfig)
	if err != nil {
		return defaultMultilineConfigProvider(), errors.New("A valid kubernetes configuration has not been provided")
	}

	defaultDockerConfig, err := getDockerConfig(multilineConfig)
	if err != nil {
		return defaultMultilineConfigProvider(), errors.New("A valid docker configuration has not been provided")
	}

	containerJson, err := getContainerJsonFromSourcePath(&defaultDockerConfig, source)
	if err != nil {
		return defaultMultilineConfigProvider(), err
	}

	podName := containerJson.Config.Labels["io.kubernetes.pod.name"]
	podNameSpace := containerJson.Config.Labels["io.kubernetes.pod.namespace"]

	annotations, err := getKubernetesPod(config, podName, podNameSpace)
	if err != nil {
		return defaultMultilineConfigProvider(), err
	}

	patternFromPod := annotations[config.PatternAnnotation]
	negate, _ := strconv.ParseBool(annotations[config.NegateAnnotation])
	matchFromPod := annotations[config.MatcherAnnotation]

	// if the patterns or match parameters could not be found, it is safe
	// to have every line as a single entry
	if patternFromPod == "" || matchFromPod == "" {
		return defaultMultilineConfigProvider(), nil
	}

	pattern := match.MustCompile(patternFromPod)

	return MultilineConfigProvider{
		pattern,
		negate,
		matchFromPod,
	}, nil
}

func createDockerProvider(multilineConfig *MultilineConfig, source string) (MultilineConfigProvider, error) {
	config, err := getDockerConfig(multilineConfig)
	if err != nil {
		return defaultMultilineConfigProvider(), errors.New("A valid docker configuration has not been provided")
	}

	containerJson, err := getContainerJsonFromSourcePath(&config, source)
	if err != nil {
		return defaultMultilineConfigProvider(), err
	}

	patternFromPod := containerJson.Config.Labels[config.PatternLabel]
	negate, _ := strconv.ParseBool(containerJson.Config.Labels[config.NegateLabel])
	matchFromPod := containerJson.Config.Labels[config.MatcherLabel]

	// if the patterns or match parameters could not be found, it is safe
	// to have every line as a single entry
	if patternFromPod == "" || matchFromPod == "" {
		return defaultMultilineConfigProvider(), nil
	}

	pattern := match.MustCompile(patternFromPod)

	return MultilineConfigProvider{
		pattern,
		negate,
		matchFromPod,
	}, nil

}

func getContainerJsonFromSourcePath(dockerConfig *DockerConfig, source string) (*types.ContainerJSON, error) {
	logsConfig := dockerConfig.LogsPath
	if logsConfig[len(logsConfig)-1:] != "/" {
		logsConfig = logsConfig + "/"
	}

	var cid = ""
	if strings.Contains(source, logsConfig) {
		//Docker container is 64 chars in length
		cid = source[len(logsConfig) : len(logsConfig)+64]
	}
	if cid == "" {
		return nil, errors.New("Could not parse container id from source file")
	}
	containerJson, error := getContainerJsonFromContainerId(dockerConfig, cid)

	if error != nil {
		return nil, error
	}

	return containerJson, nil
}

func getDockerConfig(multilineConfig *MultilineConfig) (DockerConfig, error) {
	defaultDockerConfig := defaultDockerConfig()
	dockerConfig := multilineConfig.Docker
	if dockerConfig == nil {
		dockerConfig = common.NewConfig()
	}
	err := dockerConfig.Unpack(&defaultDockerConfig)
	return defaultDockerConfig, err
}

func getKubernetesConfig(multilineConfig *MultilineConfig) (KubernetesConfig, error) {
	config := defaultKubernetesConfig()
	kubeConfig := multilineConfig.Kubernetes
	if kubeConfig == nil {
		kubeConfig = common.NewConfig()
	}
	err := kubeConfig.Unpack(&kubeConfig)
	return config, err
}

func getKubernetesClient(config KubernetesConfig) (*k8s.Client, error) {
	if config.InCluster {
		return k8s.NewInClusterClient()
	} else {
		data, err := ioutil.ReadFile(config.KubeConfig)
		if err != nil {
			return nil, err
		}

		// Unmarshal YAML into a Kubernetes multilineConfig object.
		var config k8s.Config
		if err = yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("unmarshal kubeconfig: %v", err)
		}
		return k8s.NewClient(&config)
		return nil, err
	}
}

func createDefaultProvider(config *MultilineConfig, containerId string) (MultilineConfigProvider, error) {
	return MultilineConfigProvider{
		*config.Pattern,
		config.Negate,
		config.Match,
	}, nil
}

func defaultMultilineConfigProvider() MultilineConfigProvider {
	pattern := match.MustCompile("^[.*]")
	return MultilineConfigProvider{
		match:   "after",
		pattern: pattern,
		negate:  true,
	}
}

var getContainerJsonFromContainerId = func(dockerConfig *DockerConfig, cid string) (*types.ContainerJSON, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tls := dockerConfig.TLS
	var httpClient *http.Client
	if tls != nil {
		options := tlsconfig.Options{
			CAFile:   tls.CA,
			CertFile: tls.Certificate,
			KeyFile:  tls.Key,
		}

		tlsc, err := tlsconfig.Client(options)
		if err != nil {
			return nil, err
		}

		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsc,
			},
		}
	}
	dockerClient, error := client.NewClient(dockerConfig.Host, dockerAPIVersion, httpClient, nil)
	if error != nil {
		return nil, error
	}
	json, err := dockerClient.ContainerInspect(ctx, cid)
	return  &json, err
}

var getKubernetesPod = func(kubernetesConfig KubernetesConfig, podName string, podNameSpace string)(map[string]string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := getKubernetesClient(kubernetesConfig)
	if err != nil {
		return nil, err
	}
	pod, err := client.CoreV1().GetPod(ctx, podName, podNameSpace)
	if err != nil {
		return nil, err
	}
	return pod.Metadata.Annotations, err
}
