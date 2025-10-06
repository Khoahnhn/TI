package udm

import "strings"

type User struct {
	UserID                string    `json:"userid,omitempty"`
	GroupID               string    `json:"groupid,omitempty"`
	FirstName             string    `json:"first_name,omitempty"`
	MiddleName            string    `json:"middle_name,omitempty"`
	LastName              string    `json:"last_name,omitempty"`
	EmployeeID            string    `json:"employee_id,omitempty"`
	Title                 string    `json:"title,omitempty"`
	CompanyName           string    `json:"company_name,omitempty"`
	Managers              []*User   `json:"managers,omitempty"`
	EmailAddresses        []string  `json:"email_addresses,omitempty"`
	PhoneNumbers          []string  `json:"phone_numbers,omitempty"`
	PersonalAddress       *Location `json:"personal_address,omitempty"`
	OfficeAddress         *Location `json:"office_address,omitempty"`
	AccountExpirationTime int64     `json:"account_expiration_time,omitempty"`
	AccountLockoutTime    int64     `json:"account_lockout_time,omitempty"`
}

func (inst *User) Flatten() map[string]interface{} {
	flattened := make(map[string]interface{})

	names := make([]string, 0)
	for _, name := range []string{inst.FirstName, inst.MiddleName, inst.LastName} {
		if len(name) > 0 {
			names = append(names, name)
		}
	}
	flattened["Name"] = strings.Join(names, " ")

	if inst.CompanyName != "" {
		flattened["Organization"] = inst.CompanyName
	}

	if len(inst.EmailAddresses) > 0 {
		emails := make([]string, 0)
		for _, email := range inst.EmailAddresses {
			email = strings.TrimSpace(email)
			if email != "" {
				emails = append(emails, email)
			}
		}
		if len(emails) > 0 {
			flattened["Contact Email"] = inst.EmailAddresses
		}
	}

	if len(inst.PhoneNumbers) > 0 {
		phones := make([]string, 0)
		for _, phone := range inst.PhoneNumbers {
			phone = strings.TrimSpace(phone)
			if phone != "" {
				phones = append(phones, phone)
			}
		}
		if len(phones) > 0 {
			flattened["Contact Phone"] = inst.PhoneNumbers
		}
	}

	if inst.PersonalAddress != nil {
		flattenedPersonalAddress := inst.PersonalAddress.Flatten()
		if flattenedPersonalAddress["Address"] != "" {
			flattened["Contact Personal Address"] = flattenedPersonalAddress["Address"]
		}
		if flattenedPersonalAddress["Coordinates"] != "" {
			flattened["Contact Personal Coordinates"] = flattenedPersonalAddress["Coordinates"]
		}
	}

	if inst.OfficeAddress != nil {
		flattenedOfficeAddress := inst.OfficeAddress.Flatten()
		if flattenedOfficeAddress["Address"] != "" {
			flattened["Contact Office Address"] = flattenedOfficeAddress["Address"]
		}
		if flattenedOfficeAddress["Coordinates"] != "" {
			flattened["Contact Office Coordinates"] = flattenedOfficeAddress["Coordinates"]
		}
	}
	// Success
	return flattened
}
