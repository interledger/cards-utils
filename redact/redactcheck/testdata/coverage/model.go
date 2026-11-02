package model

type Merchant struct {
	ID        string
	VatNumber *string `sensitive:"confidential"`
	Email     string
	KCV       string
	Notes     string `sensitive:"secret-ish"`
}

type Location struct {
	VatNumber *string `sensitive:"pii"`
}
