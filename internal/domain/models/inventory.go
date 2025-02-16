package models

type Inventory struct {
	ID       int `json:"id"`
	UserID   int `json:"user_id"`
	MerchID  int `json:"merch_id"`
	Quantity int `json:"quantity"`
}
