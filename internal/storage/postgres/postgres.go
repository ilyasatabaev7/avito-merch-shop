package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/domain/models"
	_ "github.com/lib/pq"
	"log/slog"
	"sync"
)

type Storage struct {
	db     *sql.DB
	logger *slog.Logger
}

func New(dbUrl string) (*Storage, error) {
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		return nil, fmt.Errorf("database connection error %s", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect database error %s", err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) Stop() error {
	return s.db.Close()
}

func (s *Storage) SaveUser(ctx context.Context, username string, passHash []byte) error {
	const op = "storage.postgres.SaveUser"

	stmt, err := s.db.Prepare("INSERT INTO users (username, password_hash) VALUES($1, $2)")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	fmt.Println(username, string(passHash), stmt)
	_, err = stmt.ExecContext(ctx, username, passHash)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) GetUser(ctx context.Context, username string) (*models.User, error) {
	const op = "storage.postgres.GetUser"

	var user models.User

	stmt, err := s.db.Prepare("SELECT * FROM users WHERE username = $1")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	rows, err := stmt.QueryContext(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	for rows.Next() {
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Balance, &user.CreatedAt); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	return &user, nil
}

func (s *Storage) SaveTransaction(ctx context.Context, senderUserID, receiverUserID, amount int) error {
	const op = "storage.postgres.SaveTransaction"

	stmt, err := s.db.Prepare("INSERT INTO transactions(sender_id, receiver_id, amount) VALUES($1, $2, $3)")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmt.ExecContext(ctx, senderUserID, receiverUserID, amount)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) GetMerch(ctx context.Context, item string) (*models.Merch, error) {
	const op = "storage.postgres.GetMerch"

	var merch models.Merch

	stmt, err := s.db.Prepare("SELECT * FROM merch WHERE name = $1")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	rows, err := stmt.QueryContext(ctx, item)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	for rows.Next() {
		var merchItem models.Merch
		if err := rows.Scan(&merchItem.ID, &merchItem.Name, &merchItem.Price); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		merch = merchItem
	}

	return &merch, nil
}

func (s *Storage) FirstBuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	const op = "storage.postgres.BuyItem"

	stmt, err := s.db.Prepare("INSERT INTO inventory(user_id, merch_id, quantity) VALUES($1, $2, $3)")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmt.ExecContext(ctx, userID, itemID, 1)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	err = s.UpdateBalance(ctx, userID, -amount)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) BuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	const op = "storage.postgres.BuyItem"

	stmt, err := s.db.Prepare("UPDATE inventory SET quantity = quantity + 1 WHERE user_id = $1 AND merch_id = $2")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmt.ExecContext(ctx, userID, itemID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	err = s.UpdateBalance(ctx, userID, -amount)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) UpdateBalance(ctx context.Context, userID int, amount int) error {
	const op = "storage.postgres.UpdateBalance"

	stmt, err := s.db.Prepare("UPDATE users SET balance = balance + $1 WHERE id = $2")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = stmt.ExecContext(ctx, amount, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// LoadCacheFromDB loads cache that contains users by their username from database
func (s *Storage) LoadCacheFromDB(cache *sync.Map, log *slog.Logger) error {
	rows, err := s.db.Query("SELECT * FROM users")
	if err != nil {
		return err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Error("Failed to close users rows", "error", err)
		}
	}(rows)

	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Balance, &user.CreatedAt); err != nil {
			return err
		}

		merch := make(map[int]models.Merch)
		merchRows, err := s.db.Query("SELECT * FROM merch")
		if err != nil {
			return err
		}
		defer func(merchRows *sql.Rows) {
			err := merchRows.Close()
			if err != nil {
				log.Error("Failed to close merch rows", "error", err)
			}
		}(merchRows)
		for merchRows.Next() {
			var m models.Merch
			if err := merchRows.Scan(&m.ID, &m.Name, &m.Price); err != nil {
				return err
			}
			merch[m.ID] = m
		}

		inventories := make(map[string]int)
		inventoriesRows, err := s.db.Query("SELECT * FROM inventory WHERE user_id = $1", user.ID)
		if err != nil {
			return err
		}
		defer func(inventoriesRows *sql.Rows) {
			err := inventoriesRows.Close()
			if err != nil {
				log.Error("Failed to close inventories rows", "error", err)
			}
		}(inventoriesRows)
		for inventoriesRows.Next() {
			var inventory models.Inventory
			if err := inventoriesRows.Scan(&inventory.ID, &inventory.UserID, &inventory.MerchID, &inventory.Quantity); err != nil {
				return err
			}
			inventories[merch[inventory.MerchID].Name] = inventory.Quantity
		}
		user.Inventory = inventories

		transactionsRows, err := s.db.Query("SELECT * FROM transactions WHERE sender_id = $1 OR receiver_id = $1", user.ID)
		if err != nil {
			return err
		}
		defer func(transactionsRows *sql.Rows) {
			err := transactionsRows.Close()
			if err != nil {
				log.Error("Failed to close transactions rows", "error", err)
			}
		}(transactionsRows)
		for transactionsRows.Next() {
			var transaction models.Transaction
			if err := transactionsRows.Scan(&transaction.ID, &transaction.SenderID, &transaction.ReceiverID, &transaction.Amount, &transaction.CreatedAt); err != nil {
				return err
			}
			if transaction.SenderID == user.ID && transaction.Amount != 0 {
				user.SentTransactions = append(user.SentTransactions, transaction)
			}
			if transaction.ReceiverID == user.ID && transaction.Amount != 0 {
				user.ReceivedTransactions = append(user.ReceivedTransactions, transaction)
			}
		}
		cache.Store(user.ID, user)
	}
	return nil
}
