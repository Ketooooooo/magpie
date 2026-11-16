package pii

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/plugin"
)

const pluginModelPrefix = externalPrefix + "plugin/"

var pluginModels struct {
	sync.Mutex
	stamp string
	list  []*externalModel
}

func init() {
	plugin.OnChange(func() { registeredPluginModels() })
}

// registeredPluginModels keeps a helper and its cache while its effective
// configuration stays the same. Install, options, updates and disable are
// picked up across Magpie processes through the plugin store's stamp.
func registeredPluginModels() []*externalModel {
	pluginModels.Lock()
	stamp := plugin.ListStamp()
	if pluginModels.stamp == stamp {
		list := pluginModels.list
		pluginModels.Unlock()
		return list
	}
	previous := make(map[string]*externalModel, len(pluginModels.list))
	for _, m := range pluginModels.list {
		previous[m.id] = m
	}
	var list []*externalModel
	for _, entry := range plugin.Load().Plugins {
		if entry.Off {
			continue
		}
		list = append(list, modelsFromPlugin(entry, previous)...)
	}
	for _, old := range previous {
		old.retired.Store(true)
	}
	pluginModels.stamp, pluginModels.list = stamp, list
	pluginModels.Unlock()
	for _, old := range previous {
		old.Stop()
	}
	return list
}

func modelsFromPlugin(entry plugin.Entry, previous map[string]*externalModel) []*externalModel {
	dir := plugin.Target(entry.Spec)
	launcher, _ := plugin.PrivacyModels(dir)
	if launcher == nil {
		return nil
	}
	versions, err := plugin.PrivacyVersions(entry.Options)
	if err != nil {
		log.Printf("privacy models from %s: %v", entry.Spec, err)
		return nil
	}
	command := launcher.Command
	if !filepath.IsAbs(command) && strings.ContainsAny(command, `/\`) {
		var ok bool
		if command, ok = plugin.FileIn(dir, filepath.ToSlash(command)); !ok {
			log.Printf("privacy models from %s: launcher must be a file in the plugin", entry.Spec)
			return nil
		}
	}
	owner := sha256.Sum256([]byte(plugin.Name(entry.Spec)))
	packageRevision := launcher.Version
	if plugin.IsGit(entry.Spec) {
		packageRevision += "@" + plugin.GitCommit(entry.Spec)
	}
	var list []*externalModel
	for _, v := range versions {
		id := fmt.Sprintf("%s%x/%s", pluginModelPrefix, owner[:8], v.ID)
		spec := externalSpec{
			ID: id, Name: v.Name, Command: command, Args: append(slices.Clone(launcher.Args), v.Path),
			Revision: v.Revision, MinScore: v.MinScore,
		}
		data, _ := json.Marshal(spec)
		identity := fmt.Sprintf("%x", sha256.Sum256([]byte(dir+"\x00"+packageRevision+"\x00"+string(data))))
		if old := previous[id]; old != nil && old.identity == identity {
			list = append(list, old)
			delete(previous, id)
			continue
		}
		m := &externalModel{id: id, spec: spec, dir: dir, weights: v.Path, identity: identity}
		m.initBackend(appdir.Cache())
		list = append(list, m)
	}
	return list
}
