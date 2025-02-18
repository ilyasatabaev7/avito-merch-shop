package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/config"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/domain/models"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/lib/jwt" // custom jwt functions
	"golang.org/x/crypto/bcrypt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// ========================================================
// Fake Storage for Authentication Tests
// ========================================================

// FakeAuthStorage implements the minimal storage methods needed for auth.
type FakeAuthStorage struct {
	users  map[string]*models.User
	nextID int
}

func NewFakeAuthStorage() *FakeAuthStorage {
	return &FakeAuthStorage{
		users:  make(map[string]*models.User),
		nextID: 1,
	}
}

func (fs *FakeAuthStorage) LoadCacheFromDB(cache *sync.Map, log *slog.Logger) error {
	return nil
}

func (fs *FakeAuthStorage) GetUser(ctx context.Context, username string) (*models.User, error) {
	if user, ok := fs.users[username]; ok {
		return user, nil
	}
	return nil, nil
}

func (fs *FakeAuthStorage) SaveUser(ctx context.Context, username string, passHash []byte) error {
	fs.users[username] = &models.User{
		ID:           fs.nextID,
		Username:     username,
		PasswordHash: string(passHash),
		Balance:      1000,
		Inventory:    make(map[string]int),
	}
	fs.nextID++
	return nil
}

// Stub methods to satisfy the Storage interface.
func (fs *FakeAuthStorage) SaveTransaction(ctx context.Context, senderUserID, receiverUserID, amount int) error {
	return nil
}
func (fs *FakeAuthStorage) UpdateBalance(ctx context.Context, userID int, amount int) error {
	return nil
}
func (fs *FakeAuthStorage) GetMerch(ctx context.Context, item string) (*models.Merch, error) {
	return nil, sql.ErrNoRows
}
func (fs *FakeAuthStorage) FirstBuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	return nil
}
func (fs *FakeAuthStorage) BuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	return nil
}

// ========================================================
// Dummy Storage for Info Endpoint (Not used by auth)
// ========================================================

type DummyStorage struct{}

func (ds *DummyStorage) LoadCacheFromDB(cache *sync.Map, log *slog.Logger) error {
	return nil
}
func (ds *DummyStorage) GetMerch(ctx context.Context, item string) (*models.Merch, error) {
	// For infoHandler this method is not used.
	return &models.Merch{ID: 1, Name: item, Price: 200}, nil
}
func (ds *DummyStorage) FirstBuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	return nil
}
func (ds *DummyStorage) BuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	return nil
}
func (ds *DummyStorage) GetUser(ctx context.Context, username string) (*models.User, error) {
	return nil, fmt.Errorf("not implemented")
}
func (ds *DummyStorage) SaveTransaction(ctx context.Context, senderUserID, receiverUserID, amount int) error {
	return nil
}
func (ds *DummyStorage) UpdateBalance(ctx context.Context, userID int, amount int) error {
	return nil
}
func (ds *DummyStorage) SaveUser(ctx context.Context, username string, passHash []byte) error {
	return nil
}

// ========================================================
// Dummy Storage for Buy Item Endpoint
// ========================================================

type DummyBuyStorage struct{}

func (ds *DummyBuyStorage) LoadCacheFromDB(cache *sync.Map, log *slog.Logger) error {
	return nil
}
func (ds *DummyBuyStorage) GetMerch(ctx context.Context, item string) (*models.Merch, error) {
	// Return a merch item with price 200.
	return &models.Merch{ID: 1, Name: item, Price: 200}, nil
}
func (ds *DummyBuyStorage) FirstBuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	return nil
}
func (ds *DummyBuyStorage) BuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	return nil
}
func (ds *DummyBuyStorage) GetUser(ctx context.Context, username string) (*models.User, error) {
	return nil, fmt.Errorf("not implemented")
}
func (ds *DummyBuyStorage) SaveTransaction(ctx context.Context, senderUserID, receiverUserID, amount int) error {
	return nil
}
func (ds *DummyBuyStorage) UpdateBalance(ctx context.Context, userID int, amount int) error {
	return nil
}
func (ds *DummyBuyStorage) SaveUser(ctx context.Context, username string, passHash []byte) error {
	return nil
}

// ========================================================
// Dummy Storage for Send Coin Endpoint
// ========================================================

type DummySendCoinStorage struct{}

func (ds *DummySendCoinStorage) LoadCacheFromDB(cache *sync.Map, log *slog.Logger) error {
	return nil
}
func (ds *DummySendCoinStorage) GetMerch(ctx context.Context, item string) (*models.Merch, error) {
	return nil, fmt.Errorf("not implemented")
}
func (ds *DummySendCoinStorage) FirstBuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	return nil
}
func (ds *DummySendCoinStorage) BuyItem(ctx context.Context, userID int, itemID int, amount int) error {
	return nil
}
func (ds *DummySendCoinStorage) GetUser(ctx context.Context, username string) (*models.User, error) {
	// For sendCoin endpoint, if the receiver is "receiver", return a dummy user.
	if username == "receiver" {
		return &models.User{
			ID:        2,
			Username:  "receiver",
			Balance:   500,
			Inventory: make(map[string]int),
		}, nil
	}
	return nil, fmt.Errorf("user not found")
}
func (ds *DummySendCoinStorage) SaveTransaction(ctx context.Context, senderUserID, receiverUserID, amount int) error {
	return nil
}
func (ds *DummySendCoinStorage) UpdateBalance(ctx context.Context, userID int, amount int) error {
	return nil
}
func (ds *DummySendCoinStorage) SaveUser(ctx context.Context, username string, passHash []byte) error {
	return nil
}

// ========================================================
// Tests for Auth Handlers (Registration & Login)
// ========================================================

func TestAuthRegistration(t *testing.T) {
	// Use FakeAuthStorage so that GetUser returns nil (user not found)
	fakeStorage := NewFakeAuthStorage()
	dummyCache := &sync.Map{}
	cfg := &config.Config{ApiHost: "localhost", ApiPort: 8080}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	jwtSecret := []byte("secret")
	apiServer := New(cfg, logger, dummyCache, fakeStorage, jwtSecret)

	reqBody := map[string]string{
		"username": "newuser",
		"password": "password",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/auth", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	// Wrap handler so ServeHTTP is available.
	handler := http.HandlerFunc(apiServer.authHandler())
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}

	claims, err := jwt.ParseToken(resp.Token, string(jwtSecret))
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if claims["username"] != "newuser" {
		t.Errorf("expected username 'newuser', got %v", claims["username"])
	}
}

func TestAuthLogin(t *testing.T) {
	fakeStorage := NewFakeAuthStorage()
	dummyCache := &sync.Map{}
	cfg := &config.Config{ApiHost: "localhost", ApiPort: 8080}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	jwtSecret := []byte("secret")
	apiServer := New(cfg, logger, dummyCache, fakeStorage, jwtSecret)

	password := "password"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	fakeStorage.users["existing"] = &models.User{
		ID:           1,
		Username:     "existing",
		PasswordHash: string(hashed),
		Balance:      1000,
		Inventory:    make(map[string]int),
	}

	reqBody := map[string]string{
		"username": "existing",
		"password": "password",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/auth", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(apiServer.authHandler())
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 for valid login, got %d", rr.Code)
	}

	var resp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token for valid login")
	}

	wrongReqBody := map[string]string{
		"username": "existing",
		"password": "wrongpassword",
	}
	body, err = json.Marshal(wrongReqBody)
	if err != nil {
		t.Fatalf("failed to marshal wrong request body: %v", err)
	}
	req = httptest.NewRequest("POST", "/api/auth", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(apiServer.authHandler())
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for invalid login, got %d", rr.Code)
	}
}

// ========================================================
// Test for Info Handler
// ========================================================

func TestInfoHandler(t *testing.T) {
	dummyStore := &DummyStorage{}
	dummyCache := &sync.Map{}
	cfg := &config.Config{ApiHost: "localhost", ApiPort: 8080}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	jwtSecret := []byte("secret")
	apiServer := New(cfg, logger, dummyCache, dummyStore, jwtSecret)

	testUser := models.User{
		ID:       1,
		Username: "test",
		Balance:  800,
		Inventory: map[string]int{
			"tshirt": 2,
		},
		ReceivedTransactions: []models.Transaction{
			{Amount: 150, SenderID: 2},
		},
		SentTransactions: []models.Transaction{
			{Amount: 200, ReceiverID: 2},
		},
	}
	otherUser := models.User{
		ID:        2,
		Username:  "other",
		Balance:   1200,
		Inventory: map[string]int{},
	}
	dummyCache.Store(testUser.ID, testUser)
	dummyCache.Store(otherUser.ID, otherUser)

	token, err := jwt.NewToken(&testUser, string(jwtSecret), 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/info", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(apiServer.authenticate(apiServer.infoHandler()))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var resp InfoResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode info response: %v", err)
	}

	if resp.Balance != testUser.Balance {
		t.Errorf("expected balance %d, got %d", testUser.Balance, resp.Balance)
	}
	if qty, ok := resp.Inventory["tshirt"]; !ok || qty != 2 {
		t.Errorf("expected inventory tshirt:2, got %v", resp.Inventory)
	}
	if len(resp.CoinHistory.Received) != 1 {
		t.Errorf("expected 1 received transaction, got %d", len(resp.CoinHistory.Received))
	} else {
		rt := resp.CoinHistory.Received[0]
		if rt.FromUser != "other" || rt.Amount != 150 {
			t.Errorf("unexpected received transaction: %+v", rt)
		}
	}
	if len(resp.CoinHistory.Sent) != 1 {
		t.Errorf("expected 1 sent transaction, got %d", len(resp.CoinHistory.Sent))
	} else {
		st := resp.CoinHistory.Sent[0]
		if st.ToUser != "other" || st.Amount != 200 {
			t.Errorf("unexpected sent transaction: %+v", st)
		}
	}
}

// ========================================================
// Test for Buy Item Handler
// ========================================================

func TestBuyItemHandler(t *testing.T) {
	dummyStorage := &DummyBuyStorage{}
	dummyCache := &sync.Map{}
	cfg := &config.Config{ApiHost: "localhost", ApiPort: 8080}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	jwtSecret := []byte("secret")
	apiServer := New(cfg, logger, dummyCache, dummyStorage, jwtSecret)

	testUser := models.User{
		ID:        1,
		Username:  "buyer",
		Balance:   1000,
		Inventory: make(map[string]int),
	}
	dummyCache.Store(testUser.ID, testUser)

	token, err := jwt.NewToken(&testUser, string(jwtSecret), 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/buy/tshirt", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req = mux.SetURLVars(req, map[string]string{"item": "tshirt"})
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(apiServer.authenticate(apiServer.buyItemHandler()))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	updatedUserInterface, ok := dummyCache.Load(testUser.ID)
	if !ok {
		t.Fatalf("user not found in cache after purchase")
	}
	updatedUser := updatedUserInterface.(models.User)
	expectedBalance := 1000 - 200
	if updatedUser.Balance != expectedBalance {
		t.Errorf("expected balance %d, got %d", expectedBalance, updatedUser.Balance)
	}
	if qty, exists := updatedUser.Inventory["tshirt"]; !exists || qty != 1 {
		t.Errorf("expected inventory for 'tshirt' to be 1, got %d", qty)
	}
}

// ========================================================
// Test for Send Coin Handler
// ========================================================

func TestSendCoinHandler(t *testing.T) {
	dummyStorage := &DummySendCoinStorage{}
	dummyCache := &sync.Map{}
	cfg := &config.Config{ApiHost: "localhost", ApiPort: 8080}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	jwtSecret := []byte("secret")
	apiServer := New(cfg, logger, dummyCache, dummyStorage, jwtSecret)

	sender := models.User{
		ID:        1,
		Username:  "sender",
		Balance:   1000,
		Inventory: make(map[string]int),
	}
	dummyCache.Store(sender.ID, sender)

	token, err := jwt.NewToken(&sender, string(jwtSecret), 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	reqBody := map[string]interface{}{
		"toUser": "receiver",
		"amount": 300,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/sendCoin", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(apiServer.authenticate(apiServer.sendCoinHandler()))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	updatedSenderInterface, ok := dummyCache.Load(sender.ID)
	if !ok {
		t.Fatalf("sender not found in cache after sending coin")
	}
	updatedSender := updatedSenderInterface.(models.User)
	expectedSenderBalance := 1000 - 300
	if updatedSender.Balance != expectedSenderBalance {
		t.Errorf("expected sender balance %d, got %d", expectedSenderBalance, updatedSender.Balance)
	}

	updatedReceiverInterface, ok := dummyCache.Load(2)
	if !ok {
		t.Fatalf("receiver not found in cache after sending coin")
	}
	updatedReceiver := updatedReceiverInterface.(models.User)
	expectedReceiverBalance := 500 + 300
	if updatedReceiver.Balance != expectedReceiverBalance {
		t.Errorf("expected receiver balance %d, got %d", expectedReceiverBalance, updatedReceiver.Balance)
	}
}
