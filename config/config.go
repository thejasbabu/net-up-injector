package config

type WebHook struct {
	Port                  int    `default:"443"`
	LogLevel              string `split_words:"true" default:"info"`
	CertFile              string `split_words:"true" required:"true"`
	CertKey               string `split_words:"true" required:"true"`
	SideCarTemplateFile   string `split_words:"true" default:"./template/sidecarContainer.tmpl"`
	SidecarContainerImage string `split_words:"true" required:"true"`
}
