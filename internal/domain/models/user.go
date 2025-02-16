package models

type User struct {
	ID           int            `json:"id"`
	Username     string         `json:"username"`
	PasswordHash string         `json:"password_hash"`
	Balance      int            `json:"balance"`
	CreatedAt    string         `json:"created_at"`
	Inventory    map[string]int `json:"inventory"`
	Transactions []Transaction  `json:"transactions"`
	CoinReceived int            `json:"coin_received"`
	CoinSent     int            `json:"coin_sent"`
}
