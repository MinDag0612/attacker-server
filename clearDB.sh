echo "[INFOR] Clearing database..."

docker compose down
docker volume rm attacker-server_mysql_data
docker compose up -d