Запуск:
- go run ./cmd/migrator -db-url="ilyas:324153@localhost:5433/avito_merch_shop_db"
- go run ./cmd/api -config="./config/local.yml"

Для ускорения апи добавил кеширование при этом использовал sync.Map для кеширования пользователей в памяти