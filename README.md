# User Authentication API
API sederhana untuk user authentication menggunakan JWT dan bcrypt dengan bahasa Golang.

## Tech Stack
- Golang
- Gin Framework
- GORM (PostgreSQL)
- Bcrypt
- JWT

## Fitur
- Register  
- Login  
- Logout  
- Proteksi API dengan JWT  
- Hashing Password dengan Bcrypt  

## Instalasi
1. Clone project ini:
```bash
git clone https://github.com/FahmiHeykal/user-auth-api.git
cd user-auth-api
```

2. Install dependencies:
```bash
go mod tidy
```

3. Konfigurasi Database (PostgreSQL):
Buka file **main.go** dan edit bagian koneksi:
```go
dsn := "host=localhost user=your_user password=your_password dbname=your_db port=5432 sslmode=disable"
```

4. Jalankan API:
```bash
go run main.go
```

## Endpoint API
| Method | Endpoint       | Deskripsi         | Proteksi |
|--------|----------------|-------------------|----------|
| POST   | /register      | Register User     | ❌       |
| POST   | /login         | Login User        | ❌       |
| GET    | /api/protected | Endpoint Proteksi | ✅ JWT   |
