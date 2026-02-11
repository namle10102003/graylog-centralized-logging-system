# Hướng dẫn chạy Graylog bằng Docker Compose

## Yêu cầu hệ thống

- Docker Desktop (Windows/Mac) hoặc Docker Engine (Linux)
- Docker Compose v2.0+
- Ít nhất 4GB RAM khả dụng
- Cổng 9000, 1514, 12201, 5555 chưa được sử dụng

## Cấu trúc thành phần

| Service    | Image                               | Mô tả                                |
| ---------- | ----------------------------------- | ------------------------------------ |
| mongo      | mongo:5.0                           | MongoDB - Lưu trữ metadata           |
| opensearch | opensearchproject/opensearch:2.11.1 | OpenSearch - Lưu trữ và tìm kiếm log |
| graylog    | graylog/graylog:5.2                 | Graylog Server (Backend + Frontend)  |

## Các bước chạy

### 1. Cấu hình môi trường

Chỉnh sửa file `.env` để thay đổi password:

```bash
# Tạo PASSWORD_SECRET mới (cần ít nhất 16 ký tự)
# Windows PowerShell:
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(64))

# Linux/Mac:
openssl rand -base64 64 | tr -d '\n'
```

```bash
# Tạo SHA256 hash cho password admin
# Windows PowerShell:
$password = "your_admin_password"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($password)
$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
-join ($hash | ForEach-Object { $_.ToString("x2") })

# Linux/Mac:
echo -n "your_admin_password" | sha256sum | cut -d" " -f1
```

### 2. Khởi động tất cả services

```bash
# Di chuyển tới thư mục chứa docker-compose.yml
cd graylog2-server

# Khởi động tất cả containers ở chế độ nền
docker-compose up -d

# Hoặc với Docker Compose v2
docker compose up -d
```

### 3. Kiểm tra trạng thái

```bash
# Xem trạng thái các containers
docker-compose ps

# Xem logs của tất cả services
docker-compose logs -f

# Xem logs của từng service
docker-compose logs -f graylog
docker-compose logs -f opensearch
docker-compose logs -f mongo
```

### 4. Truy cập Graylog

- **URL**: http://localhost:9000
- **Username**: `admin`
- **Password**: `10102003` (hoặc password bạn đã cấu hình trong .env)

⚠️ **Lưu ý**: Graylog cần khoảng 1-2 phút để khởi động hoàn toàn. Nếu không truy cập được, hãy đợi và thử lại.

## Cấu hình Input để nhận log

Sau khi đăng nhập vào Graylog:

1. Vào **System** → **Inputs**
2. Chọn loại input phù hợp:
   - **Syslog UDP/TCP** (cổng 1514)
   - **GELF UDP/TCP** (cổng 12201)
   - **Raw/Plaintext UDP/TCP** (cổng 5555)
3. Click **Launch new input**
4. Cấu hình và **Save**

## Gửi log test

```bash
# Gửi log qua GELF (UDP)
echo '{"version": "1.1","host":"test-host","short_message":"Test message","level":1}' | nc -u -w1 localhost 12201

# Gửi log qua Syslog (UDP)
echo "<14>Test syslog message" | nc -u -w1 localhost 1514

# Gửi log qua Raw TCP
echo "Test raw message" | nc localhost 5555
```

## Các lệnh quản lý

```bash
# Dừng tất cả services
docker-compose stop

# Khởi động lại
docker-compose start

# Dừng và xóa containers (giữ data)
docker-compose down

# Dừng và xóa tất cả (bao gồm cả volumes/data)
docker-compose down -v

# Restart một service cụ thể
docker-compose restart graylog

# Cập nhật image mới
docker-compose pull
docker-compose up -d
```

## Troubleshooting

### OpenSearch không khởi động được

```bash
# Linux: Tăng vm.max_map_count
sudo sysctl -w vm.max_map_count=262144

# Windows với WSL2: Chạy trong WSL
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

### Graylog không kết nối được OpenSearch

```bash
# Kiểm tra OpenSearch đã sẵn sàng chưa
curl http://localhost:9200

# Restart Graylog sau khi OpenSearch đã sẵn sàng
docker-compose restart graylog
```

### Xem log chi tiết

```bash
docker-compose logs --tail=100 graylog
```

## Cổng được expose

| Cổng  | Protocol | Mô tả                    |
| ----- | -------- | ------------------------ |
| 9000  | TCP      | Web Interface & REST API |
| 1514  | TCP/UDP  | Syslog input             |
| 12201 | TCP/UDP  | GELF input               |
| 5555  | TCP/UDP  | Raw/Plaintext input      |

## Volumes (Dữ liệu persistent)

| Volume          | Mô tả                   |
| --------------- | ----------------------- |
| mongo_data      | Dữ liệu MongoDB         |
| os_data         | Dữ liệu OpenSearch      |
| graylog_data    | Dữ liệu Graylog         |
| graylog_journal | Graylog message journal |
