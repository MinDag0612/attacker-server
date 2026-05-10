echo "[INFOR] Clearing database..."

docker compose down
docker volume rm attacker_db_data
docker compose up -d