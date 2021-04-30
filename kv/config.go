package kv

import (
	db "ulambda/debug"
	"ulambda/fslib"
)

type Config struct {
	N      int
	Shards []string // maps shard # to server
}

type Config2 struct {
	N   int
	Old []string
	New []string
}

func makeConfig(n int) *Config {
	cf := &Config{n, make([]string, NSHARD)}
	return cf
}

func (cf *Config) present(n string) bool {
	for _, s := range cf.Shards {
		if s == n {
			return true
		}
	}
	return false
}

func readConfig(fsl *fslib.FsLib, conffile string) (*Config, error) {
	conf := Config{}
	err := fsl.ReadFileJson(conffile, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}

func readConfig2(fsl *fslib.FsLib, conffile string) (*Config2, error) {
	conf := Config2{}
	err := fsl.ReadFileJson(conffile, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}

type KvSet struct {
	set map[string]bool
}

func makeKvs(shards []string) *KvSet {
	ks := &KvSet{}
	ks.set = make(map[string]bool)
	for _, kv := range shards {
		if _, ok := ks.set[kv]; !ok && kv != "" {
			ks.set[kv] = true
		}
	}
	return ks
}

func (ks *KvSet) mkKvs() []string {
	kvs := make([]string, 0, len(ks.set))
	for kv, _ := range ks.set {
		kvs = append(kvs, kv)
	}
	return kvs
}

func (ks *KvSet) add(new []string) {
	for _, kv := range new {
		ks.set[kv] = true
	}
}

func (ks *KvSet) del(old []string) {
	for _, kv := range old {
		delete(ks.set, kv)
	}
}

// XXX minimize movement
func balance(conf *Config, kvs *KvSet) *Config2 {
	j := 0
	cfg2 := &Config2{}
	cfg2.N = conf.N + 1
	cfg2.Old = conf.Shards
	cfg2.New = make([]string, NSHARD)

	db.DLPrintf("SHARDER", "balance %v (len %v) kvs %v\n", conf.Shards,
		len(conf.Shards), kvs)

	nextkvs := kvs.mkKvs()
	if len(nextkvs) == 0 {
		return cfg2
	}

	for i, _ := range conf.Shards {
		cfg2.New[i] = nextkvs[j]
		j = (j + 1) % len(nextkvs)
	}
	return cfg2
}
