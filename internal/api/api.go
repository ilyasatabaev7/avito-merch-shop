package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/config"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/domain/models"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/lib/jwt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Storage interface {
	SaveUser(ctx context.Context, username string, passHash []byte) error
	GetUser(ctx context.Context, username string) (*models.User, error)
	GetMerch(ctx context.Context, item string) (*models.Merch, error)
	FirstBuyItem(ctx context.Context, userID int, itemID int, amount int) error
	BuyItem(ctx context.Context, userID int, itemID int, amount int) error
	SaveTransaction(ctx context.Context, senderUserID, receiverUserID, amount int) error
	UpdateBalance(ctx context.Context, userID int, amount int) error
	LoadCacheFromDB(cache *sync.Map, log *slog.Logger) error
}

type APIServer struct {
	config    *config.Config
	logger    *slog.Logger
	cache     *sync.Map
	server    *http.Server
	storage   Storage
	jwtSecret []byte
}

func New(config *config.Config, logger *slog.Logger, cache *sync.Map, storage Storage, jwtSecret []byte) *APIServer {
	return &APIServer{
		config: config,
		logger: logger,
		cache:  cache,
		server: &http.Server{
			Addr: config.ApiHost + ":" + strconv.Itoa(config.ApiPort),
		},
		storage:   storage,
		jwtSecret: jwtSecret,
	}
}

func (s *APIServer) Start() error {
	s.logger.Info("Starting server", slog.String("port", strconv.Itoa(s.config.ApiPort)))

	s.configureRouter()

	return s.server.ListenAndServe()
}

func (s *APIServer) MustStart() {
	err := s.Start()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic("Failed to start server: " + err.Error())
	}
}

func (s *APIServer) Stop(ctx context.Context) error {
	defer s.logger.Info("Server successfully stopped")
	return s.server.Shutdown(ctx)
}

func (s *APIServer) configureRouter() {
	router := mux.NewRouter()
	router.HandleFunc("/api/info", s.authenticate(s.infoHandler())).Methods("GET")
	router.HandleFunc("/api/sendCoin", s.authenticate(s.sendCoinHandler())).Methods("POST")
	router.HandleFunc("/api/buy/{item}", s.authenticate(s.buyItemHandler())).Methods("GET")
	router.HandleFunc("/api/auth", s.authHandler()).Methods("POST")
	s.server.Handler = router
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

func (s *APIServer) authHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
			return
		}

		user, err := s.storage.GetUser(context.Background(), req.Username)
		expirationTime := 24 * time.Hour

		if user == nil || user.Username == "" {
			user, err := s.registerNewUser(req.Username, []byte(req.Password))
			if err != nil {
				http.Error(w, "Ошибка регистрации", http.StatusInternalServerError)
				return
			}

			token, err := jwt.NewToken(user, string(s.jwtSecret), expirationTime)

			err = json.NewEncoder(w).Encode(AuthResponse{Token: token})
			if err != nil {
				return
			}
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))

		if err != nil {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}

		token, err := jwt.NewToken(user, string(s.jwtSecret), expirationTime)

		err = json.NewEncoder(w).Encode(AuthResponse{Token: token})
		if err != nil {
			return
		}

	}
}

func (s *APIServer) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tokenHeader := r.Header.Get("Authorization")
		if tokenHeader == "" {
			http.Error(w, "Токен отсутствует", http.StatusUnauthorized)
			return
		}
		tokenStr := tokenHeader
		parts := strings.Split(tokenHeader, " ")
		if len(parts) == 2 || parts[0] == "Bearer" {
			tokenStr = parts[1]
		}

		claims, err := jwt.ParseToken(tokenStr, string(s.jwtSecret))
		if err != nil {
			http.Error(w, "Неверный токен", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "id", int(claims["uid"].(float64))))
		next(w, r)
	}
}

func (s *APIServer) registerNewUser(username string, password []byte) (*models.User, error) {
	s.logger.Info("Register new user", slog.String("username", username))

	passHash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("Failed to hash password", "error", err)
		return nil, err
	}

	err = s.storage.SaveUser(context.Background(), username, passHash)
	if err != nil {
		s.logger.Error("Failed to save user", "error", err)
		return nil, err
	}

	user := models.User{Username: username, PasswordHash: string(passHash), Balance: 1000}
	s.cache.Store(username, user)

	return &user, nil
}

func (s *APIServer) buyItemHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		vars := mux.Vars(r)
		item := vars["item"]

		merch, err := s.storage.GetMerch(context.Background(), item)

		if err != nil {
			http.Error(w, "Товар не найден", http.StatusNotFound)
			s.logger.Error("Failed to get merch", "error", err)
			return
		}

		id := r.Context().Value("id")
		cachedUser, ok := s.cache.Load(id)

		if !ok {
			http.Error(w, "Неверный формат пользователя", http.StatusInternalServerError)
			s.logger.Error("Failed to get user", "error", err)
			return
		}

		user, ok := cachedUser.(models.User)
		if !ok {
			http.Error(w, "Неверный формат пользователя", http.StatusInternalServerError)
			s.logger.Error("Failed to get user", "error", err)
			return
		}
		if user.Balance < merch.Price {
			http.Error(w, "Недостаточно средств", http.StatusPaymentRequired)
			s.logger.Error("Unsufficient funds for purchase item", "error", err)
			return
		}

		if len(user.Inventory) == 0 {
			user.Inventory = make(map[string]int)
		}

		if _, ok := user.Inventory[item]; !ok {
			user.Inventory[item] = 0
			err = s.storage.FirstBuyItem(context.Background(), user.ID, merch.ID, merch.Price)

		} else {
			err = s.storage.BuyItem(context.Background(), user.ID, merch.ID, merch.Price)
		}

		if err != nil {
			http.Error(w, "Ошибка при покупке товара", http.StatusInternalServerError)
			s.logger.Error("Failed to buy item", "error", err)
			return
		}

		user.Inventory[item] += 1
		user.Balance -= merch.Price

		s.cache.Store(id, user)

		s.logger.Info("Buy item", slog.String("item", item))

		w.WriteHeader(http.StatusOK)
	}
}

type SendCoinRequest struct {
	ToUser string `json:"toUser"`
	Amount int    `json:"amount"`
}

func (s *APIServer) sendCoinHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req SendCoinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
			return
		}
		sender, ok := s.cache.Load(r.Context().Value("id"))

		if !ok {
			http.Error(w, "Отправитель не найден", http.StatusNotFound)
			return
		}

		senderUser, ok := sender.(models.User)
		if !ok {
			http.Error(w, "Неверный формат отправителя", http.StatusInternalServerError)
			return
		}

		if senderUser.Username == req.ToUser {
			http.Error(w, "Нельзя отправить деньги самому себе", http.StatusBadRequest)
			return
		}

		receiver, err := s.storage.GetUser(context.Background(), req.ToUser)

		if err != nil || receiver == nil {
			http.Error(w, "Получатель не найден", http.StatusNotFound)
			return
		}

		if senderUser.Balance < req.Amount {
			http.Error(w, "Недостаточно средств", http.StatusPaymentRequired)
			return
		}

		err = s.storage.SaveTransaction(context.Background(), senderUser.ID, receiver.ID, req.Amount)
		if err != nil {
			http.Error(w, "Не удалось сохранить транзакцию", http.StatusInternalServerError)
			return
		}

		err = s.storage.UpdateBalance(context.Background(), senderUser.ID, -req.Amount)
		if err != nil {
			http.Error(w, "Не удалось обновить баланс", http.StatusInternalServerError)
			return
		}

		err = s.storage.UpdateBalance(context.Background(), receiver.ID, req.Amount)
		if err != nil {
			http.Error(w, "Не удалось обновить баланс", http.StatusInternalServerError)
			return
		}

		senderUser.Balance -= req.Amount
		senderUser.SentTransactions = append(senderUser.SentTransactions, models.Transaction{
			Amount:     req.Amount,
			SenderID:   senderUser.ID,
			ReceiverID: receiver.ID,
		})
		receiver.Balance += req.Amount
		receiver.ReceivedTransactions = append(receiver.ReceivedTransactions, models.Transaction{
			Amount:     req.Amount,
			SenderID:   senderUser.ID,
			ReceiverID: receiver.ID,
		})

		s.cache.Store(r.Context().Value("id"), senderUser)
		s.cache.Store(receiver.ID, *receiver)

		s.logger.Info("Send coin", slog.Int("amount", req.Amount), slog.String("from", senderUser.Username), slog.String("to", receiver.Username))

		w.WriteHeader(http.StatusOK)
	}
}

type coinHistory struct {
	Received []models.ReceivedTransaction `json:"received"`
	Sent     []models.SentTransaction     `json:"sent"`
}

type InfoResponse struct {
	Balance     int            `json:"balance"`
	Inventory   map[string]int `json:"inventory"`
	CoinHistory coinHistory    `json:"coinHistory"`
}

func (s *APIServer) infoHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := r.Context().Value("id")
		cachedUser, ok := s.cache.Load(id)

		if !ok {
			http.Error(w, "Неверный формат пользователя", http.StatusInternalServerError)
			return
		}

		user, ok := cachedUser.(models.User)
		if !ok {
			http.Error(w, "Неверный формат пользователя", http.StatusInternalServerError)
			return
		}

		received := make([]models.ReceivedTransaction, 0)

		for _, rt := range user.ReceivedTransactions {
			cachedUser, _ := s.cache.Load(rt.SenderID)

			user, _ := cachedUser.(models.User)

			received = append(received, models.ReceivedTransaction{
				FromUser: user.Username,
				Amount:   rt.Amount,
			})
		}

		sent := make([]models.SentTransaction, 0)

		for _, st := range user.SentTransactions {
			cachedUser, _ := s.cache.Load(st.ReceiverID)
			user, _ := cachedUser.(models.User)
			fmt.Println(user.Username)
			sent = append(sent, models.SentTransaction{
				ToUser: user.Username,
				Amount: st.Amount,
			})
		}

		res := InfoResponse{
			Balance:   user.Balance,
			Inventory: user.Inventory,
			CoinHistory: coinHistory{
				Received: received,
				Sent:     sent,
			},
		}

		err := json.NewEncoder(w).Encode(res)
		if err != nil {
			return
		}
	}
}
