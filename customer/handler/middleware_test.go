package handler

import (
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestPhoneValidator(t *testing.T) {
	v := validator.New()
	v.RegisterValidation("phone", phoneValidator)

	type Phone struct {
		Number string `validate:"phone"`
	}

	tests := []struct {
		name    string
		phone   string
		wantErr bool
	}{
		{"valid digits", "0123456789", false},
		{"valid with plus", "+84123456789", false},
		{"valid with spaces", "+84 123 456 789", false},
		{"too short", "123", true},
		{"too long", "12345678901234567890", true},
		{"invalid chars", "123-456-789", true},
	}

	for _, tt := range tests {
		err := v.Struct(Phone{Number: tt.phone})
		if tt.wantErr {
			assert.Error(t, err, tt.name)
		} else {
			assert.NoError(t, err, tt.name)
		}
	}
}

func TestBusinessEmailValidator(t *testing.T) {
	// giả lập danh sách domain cá nhân
	defs.MailListPersonal = []string{"gmail.com", "yahoo.com"}

	v := validator.New()
	v.RegisterValidation("business_email", businessEmailValidator)

	type Email struct {
		Addr string `validate:"business_email"`
	}

	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid business email", "user@company.com", false},
		{"personal gmail", "user@gmail.com", true},
		{"personal yahoo", "abc@yahoo.com", true},
		{"empty email allowed", "", false},
		{"case insensitive", "User@GMAIL.com", true},
	}

	for _, tt := range tests {
		err := v.Struct(Email{Addr: tt.email})
		if tt.wantErr {
			assert.Error(t, err, tt.name)
		} else {
			assert.NoError(t, err, tt.name)
		}
	}
}
