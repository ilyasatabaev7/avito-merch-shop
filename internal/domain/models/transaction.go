package models

type Transaction struct {
	ID         int    `json:"id"`
	SenderID   int    `json:"sender_id"`
	ReceiverID int    `json:"receiver_id"`
	Amount     int    `json:"amount"`
	CreatedAt  string `json:"created_at"`
}
