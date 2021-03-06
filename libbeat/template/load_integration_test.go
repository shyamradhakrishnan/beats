// +build integration

package template

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/outputs/elasticsearch"
	"github.com/elastic/beats/libbeat/version"

	"github.com/stretchr/testify/assert"
)

func TestCheckTemplate(t *testing.T) {

	client := elasticsearch.GetTestingElasticsearch(t)

	loader := &Loader{
		client: client,
	}

	// Check for non existent template
	assert.False(t, loader.CheckTemplate("libbeat-notexists"))
}

func TestLoadTemplate(t *testing.T) {

	// Setup ES
	client := elasticsearch.GetTestingElasticsearch(t)

	// Load template
	absPath, err := filepath.Abs("../")
	assert.NotNil(t, absPath)
	assert.Nil(t, err)

	fieldsPath := absPath + "/fields.yml"
	index := "testbeat"

	tmpl, err := New(version.GetDefaultVersion(), client.GetVersion(), index, TemplateSettings{})
	assert.NoError(t, err)
	content, err := tmpl.Load(fieldsPath)
	assert.NoError(t, err)

	loader := &Loader{
		client: client,
	}

	// Load template
	err = loader.LoadTemplate(tmpl.GetName(), content)
	assert.Nil(t, err)

	// Make sure template was loaded
	assert.True(t, loader.CheckTemplate(tmpl.GetName()))

	// Delete template again to clean up
	client.Request("DELETE", "/_template/"+tmpl.GetName(), "", nil, nil)

	// Make sure it was removed
	assert.False(t, loader.CheckTemplate(tmpl.GetName()))
}

func TestLoadInvalidTemplate(t *testing.T) {

	// Invalid Template
	template := map[string]interface{}{
		"json": "invalid",
	}

	// Setup ES
	client := elasticsearch.GetTestingElasticsearch(t)

	templateName := "invalidtemplate"

	loader := &Loader{
		client: client,
	}

	// Try to load invalid template
	err := loader.LoadTemplate(templateName, template)
	assert.Error(t, err)

	// Make sure template was not loaded
	assert.False(t, loader.CheckTemplate(templateName))
}

func getTemplate(t *testing.T, client ESClient, templateName string) common.MapStr {

	status, body, err := client.Request("GET", "/_template/"+templateName, "", nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, status, 200)

	var response common.MapStr
	err = json.Unmarshal(body, &response)
	assert.NoError(t, err)

	return common.MapStr(response[templateName].(map[string]interface{}))
}

func newConfigFrom(t *testing.T, from interface{}) *common.Config {
	cfg, err := common.NewConfigFrom(from)
	assert.NoError(t, err)
	return cfg
}

// Tests loading the templates for each beat
func TestLoadBeatsTemplate(t *testing.T) {

	beats := []string{
		"libbeat",
	}

	for _, beat := range beats {
		// Load template
		absPath, err := filepath.Abs("../../" + beat)
		assert.NotNil(t, absPath)
		assert.Nil(t, err)

		// Setup ES
		client := elasticsearch.GetTestingElasticsearch(t)

		fieldsPath := absPath + "/fields.yml"
		index := beat

		tmpl, err := New(version.GetDefaultVersion(), client.GetVersion(), index, TemplateSettings{})
		assert.NoError(t, err)
		content, err := tmpl.Load(fieldsPath)
		assert.NoError(t, err)

		loader := &Loader{
			client: client,
		}

		// Load template
		err = loader.LoadTemplate(tmpl.GetName(), content)
		assert.Nil(t, err)

		// Make sure template was loaded
		assert.True(t, loader.CheckTemplate(tmpl.GetName()))

		// Delete template again to clean up
		client.Request("DELETE", "/_template/"+tmpl.GetName(), "", nil, nil)

		// Make sure it was removed
		assert.False(t, loader.CheckTemplate(tmpl.GetName()))
	}
}

func TestTemplateSettings(t *testing.T) {

	// Setup ES
	client := elasticsearch.GetTestingElasticsearch(t)

	// Load template
	absPath, err := filepath.Abs("../")
	assert.NotNil(t, absPath)
	assert.Nil(t, err)

	fieldsPath := absPath + "/fields.yml"

	settings := TemplateSettings{
		Index: common.MapStr{
			"number_of_shards": 1,
		},
		Source: common.MapStr{
			"enabled": false,
		},
	}
	tmpl, err := New(version.GetDefaultVersion(), client.GetVersion(), "testbeat", settings)
	assert.NoError(t, err)
	content, err := tmpl.Load(fieldsPath)
	assert.NoError(t, err)

	loader := &Loader{
		client: client,
	}

	// Load template
	err = loader.LoadTemplate(tmpl.GetName(), content)
	assert.Nil(t, err)

	// Check that it contains the mapping
	templateJSON := getTemplate(t, client, tmpl.GetName())
	val, err := templateJSON.GetValue("settings.index.number_of_shards")
	assert.NoError(t, err)
	assert.Equal(t, val.(string), "1")

	val, err = templateJSON.GetValue("mappings._default_._source.enabled")
	assert.NoError(t, err)
	assert.Equal(t, val.(bool), false)

	// Delete template again to clean up
	client.Request("DELETE", "/_template/"+tmpl.GetName(), "", nil, nil)

	// Make sure it was removed
	assert.False(t, loader.CheckTemplate(tmpl.GetName()))
}

func TestOverwrite(t *testing.T) {

	// Setup ES
	client := elasticsearch.GetTestingElasticsearch(t)

	beatInfo := common.BeatInfo{
		Beat:    "testbeat",
		Version: version.GetDefaultVersion(),
	}
	templateName := "testbeat-" + version.GetDefaultVersion()

	absPath, err := filepath.Abs("../")
	assert.NotNil(t, absPath)
	assert.Nil(t, err)

	// make sure no template is already there
	client.Request("DELETE", "/_template/"+templateName, "", nil, nil)

	// Load template
	config := newConfigFrom(t, TemplateConfig{
		Enabled: true,
		Fields:  absPath + "/fields.yml",
	})
	loader, err := NewLoader(config, client, beatInfo)
	assert.NoError(t, err)
	err = loader.Load()
	assert.NoError(t, err)

	// Load template again, this time with custom settings
	config = newConfigFrom(t, TemplateConfig{
		Enabled: true,
		Fields:  absPath + "/fields.yml",
		Settings: TemplateSettings{
			Source: map[string]interface{}{
				"enabled": false,
			},
		},
	})
	loader, err = NewLoader(config, client, beatInfo)
	assert.NoError(t, err)
	err = loader.Load()
	assert.NoError(t, err)

	// Overwrite was not enabled, so the first version should still be there
	templateJSON := getTemplate(t, client, templateName)
	_, err = templateJSON.GetValue("mappings._default_._source.enabled")
	assert.Error(t, err)

	// Load template again, this time with custom settings AND overwrite: true
	config = newConfigFrom(t, TemplateConfig{
		Enabled:   true,
		Overwrite: true,
		Fields:    absPath + "/fields.yml",
		Settings: TemplateSettings{
			Source: map[string]interface{}{
				"enabled": false,
			},
		},
	})
	loader, err = NewLoader(config, client, beatInfo)
	assert.NoError(t, err)
	err = loader.Load()
	assert.NoError(t, err)

	// Overwrite was enabled, so the custom setting should be there
	templateJSON = getTemplate(t, client, templateName)
	val, err := templateJSON.GetValue("mappings._default_._source.enabled")
	assert.NoError(t, err)
	assert.Equal(t, val.(bool), false)

	// Delete template again to clean up
	client.Request("DELETE", "/_template/"+templateName, "", nil, nil)
}
