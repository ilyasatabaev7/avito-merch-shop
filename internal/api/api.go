package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/config"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/domain/models"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/lib/jwt"
	"github.com/IlyasAtabaev731/avito-merch-shop/internal/storage/postgres"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type APIServer struct {
	config    *config.Config
	logger    *slog.Logger
	cache     *sync.Map
	server    *http.Server
	storage   *postgres.Storage
	jwtSecret []byte
}

func New(config *config.Config, logger *slog.Logger, cache *sync.Map, storage *postgres.Storage, jwtSecret []byte) *APIServer {
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
		var req AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
			return
		}

		cachedUser, ok := s.cache.Load(req.Username)

		if !ok {
			user, err := s.registerNewUser(req.Username, []byte(req.Password))
			if err != nil {
				http.Error(w, "Ошибка регистрации", http.StatusInternalServerError)
				return
			}

			expirationTime := 24 * time.Hour

			token, err := jwt.NewToken(user, string(s.jwtSecret), expirationTime)

			err = json.NewEncoder(w).Encode(AuthResponse{Token: token})
			if err != nil {
				return
			}
			return
		}

		user, ok := cachedUser.(models.User)
		if !ok {
			http.Error(w, "Неверный формат пользователя", http.StatusInternalServerError)
			return
		}
		err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))

		if err != nil {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			return
		}
	}
}

func (s *APIServer) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenHeader := r.Header.Get("Authorization")
		if tokenHeader == "" {
			http.Error(w, "Токен отсутствует", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(tokenHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Неверный формат токена", http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]

		claims, err := jwt.ParseToken(tokenStr, string(s.jwtSecret))
		if err != nil {
			http.Error(w, "Неверный токен", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "username", claims["username"].(string)))
		next(w, r)
	}
}

func (s *APIServer) registerNewUser(username string, password []byte) (*models.User, error) {
	s.logger.Info("Register new user", slog.String("username", username))

	passРash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("Failed to hash password", "error", err)
		return nil, err
	}

	err = s.storage.SaveUser(context.Background(), username, passРash)
	if err != nil {
		s.logger.Error("Failed to save user", "error", err)
		return nil, err
	}

	user := models.User{Username: username, PasswordHash: string(passРash), Balance: 1000}
	s.cache.Store(username, user)

	return &user, nil
}

func (s *APIServer) buyItemHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		item := vars["item"]

		merch, err := s.storage.GetMerch(context.Background(), item)

		if err != nil {
			http.Error(w, "Товар не найден", http.StatusNotFound)
			s.logger.Error("Failed to get merch", "error", err)
			return
		}

		username := r.Context().Value("username")
		cachedUser, ok := s.cache.Load(username)

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

		if _, ok := user.Inventory[item]; !ok {
			user.Inventory[item] = 0
			err = s.storage.FirstBuyItem(context.Background(), user.ID, merch.ID)

		} else {
			err = s.storage.BuyItem(context.Background(), user.ID, merch.ID)
		}

		if err != nil {
			http.Error(w, "Ошибка при покупке товара", http.StatusInternalServerError)
			s.logger.Error("Failed to buy item", "error", err)
			return
		}

		user.Inventory[item] += 1
		user.Balance -= merch.Price

		s.cache.Store(username, user)

		s.logger.Info("Buy item", slog.String("item", item))

		w.WriteHeader(http.StatusOK)
	}
}

type SendCoinRequest struct {
	toUser string
	amount int
}

func (s *APIServer) sendCoinHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SendCoinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
			return
		}
		receiver, ok := s.cache.Load(req.toUser)

		if !ok {
			http.Error(w, "Получатель не найден", http.StatusNotFound)
			return
		}

		sender, ok := s.cache.Load(r.Context().Value("username"))

		if !ok {
			http.Error(w, "Отправитель не найден", http.StatusNotFound)
			return
		}

		senderUser, ok := sender.(models.User)
		if !ok {
			http.Error(w, "Неверный формат отправителя", http.StatusInternalServerError)
			return
		}
		receiverUser, ok := receiver.(models.User)
		if !ok {
			http.Error(w, "Неверный формат получателя", http.StatusInternalServerError)
			return
		}
		if senderUser.Balance < req.amount {
			http.Error(w, "Недостаточно средств", http.StatusPaymentRequired)
			return
		}

		senderUser.Balance -= req.amount
		receiverUser.Balance += req.amount

		s.cache.Store(r.Context().Value("username"), senderUser)
		s.cache.Store(req.toUser, receiverUser)

		s.logger.Info("Send coin", slog.Int("amount", req.amount), slog.String("from", senderUser.Username), slog.String("to", receiverUser.Username))

		err := s.storage.SaveTransaction(context.Background(), senderUser.ID, receiverUser.ID, req.amount)
		if err != nil {
			http.Error(w, "Не удалось сохранить транзакцию", http.StatusInternalServerError)
			return
		}

		err = s.storage.UpdateBalance(context.Background(), senderUser.ID, -req.amount)
		if err != nil {
			http.Error(w, "Не удалось обновить баланс", http.StatusInternalServerError)
			return
		}

		err = s.storage.UpdateBalance(context.Background(), receiverUser.ID, req.amount)
		if err != nil {
			http.Error(w, "Не удалось обновить баланс", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

type coinHistory struct {
	received int
	sent     int
}

type InfoResponse struct {
	balance     int
	inventory   map[string]int
	coinHistory coinHistory
}

func (s *APIServer) infoHandler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.Context().Value("username")
		cachedUser, ok := s.cache.Load(username)

		if !ok {
			http.Error(w, "Неверный формат пользователя", http.StatusInternalServerError)
			return
		}

		user, ok := cachedUser.(models.User)
		if !ok {
			http.Error(w, "Неверный формат пользователя", http.StatusInternalServerError)
			return
		}

		res := InfoResponse{
			balance:   user.Balance,
			inventory: user.Inventory,
			coinHistory: coinHistory{
				received: user.CoinReceived,
				sent:     user.CoinSent,
			},
		}

		err := json.NewEncoder(w).Encode(res)
		if err != nil {
			return
		}
	}
}
