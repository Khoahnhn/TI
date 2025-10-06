package udm

type Registry struct {
	RegistryKey       string `json:"registry_key,omitempty"`
	RegistryValueData string `json:"registry_value_data,omitempty"`
	RegistryValueName string `json:"registry_value_name,omitempty"`
}
