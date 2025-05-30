package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/memory/v2"
	"golang.org/x/crypto/bcrypt"
)

var (
	sessionStore *session.Store
)

type User struct {
	ID           int
	Login        string
	PasswordHash string
}

var users []User

func main() {
	sessionStore = session.New(session.Config{
		Storage:        memory.New(),
		Expiration:     24 * time.Hour,
		KeyLookup:      "cookie:session_id",
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
	})

	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:8080",
		AllowHeaders:     "Origin, Content-Type, Accept, X-CSRF-Token",
		AllowCredentials: true,
	}))

	app.Use(csrf.New(csrf.Config{
		KeyLookup:      "header:X-CSRF-Token",
		CookieName:     "csrf_",
		CookieSameSite: "Lax",
		Expiration:     1 * time.Hour,
	}))

	clientDir, err := filepath.Abs("../client")
	if err != nil {
		fmt.Printf("Ошибка получения пути к client: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stat(clientDir); os.IsNotExist(err) {
		fmt.Printf("Папка client не найдена по пути: %s\n", clientDir)
		os.Exit(1)
	}

	app.Static("/", clientDir)

	app.Get("/", func(c *fiber.Ctx) error {
		filePath := filepath.Join(clientDir, "index.html")
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			fmt.Printf("Файл %s не найден\n", filePath)
			return c.Status(fiber.StatusNotFound).SendString("index.html не найден")
		}
		return c.SendFile(filePath)
	})

	app.Get("/profile", authMiddleware, func(c *fiber.Ctx) error {
		filePath := filepath.Join(clientDir, "profile.html")
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			fmt.Printf("Файл %s не найден\n", filePath)
			return c.Status(fiber.StatusNotFound).SendString("profile.html не найден")
		}
		return c.SendFile(filePath)
	})

	app.Get("/api/csrf-token", func(c *fiber.Ctx) error {
		token := c.Locals("csrf").(string)
		return c.JSON(fiber.Map{"csrfToken": token})
	})

	app.Post("/api/register", register)
	app.Post("/api/login", login)
	app.Get("/api/profile", authMiddleware, profile)
	app.Post("/api/logout", authMiddleware, logout)
	app.Get("/api/data", authMiddleware, getData)

	fmt.Println("Сервер запущен на http://localhost:8080")
	if err := app.Listen(":8080"); err != nil {
		fmt.Printf("Ошибка запуска сервера: %v\n", err)
		os.Exit(1)
	}
}

func authMiddleware(c *fiber.Ctx) error {
	sess, err := sessionStore.Get(c)
	if err != nil {
		fmt.Printf("Ошибка получения сессии: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка сессии")
	}
	userID := sess.Get("userID")
	if userID == nil {
		return c.Redirect("/", fiber.StatusFound)
	}
	return c.Next()
}

func register(c *fiber.Ctx) error {
	type Request struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	var req Request
	if err := c.BodyParser(&req); err != nil {
		fmt.Printf("Ошибка парсинга тела запроса: %v\n", err)
		return c.Status(fiber.StatusBadRequest).SendString("Неверный запрос")
	}

	if len(req.Password) < 6 {
		return c.Status(fiber.StatusBadRequest).SendString("Пароль должен содержать минимум 6 символов")
	}

	for _, user := range users {
		if user.Login == req.Login {
			return c.Status(fiber.StatusConflict).SendString("Пользователь уже существует")
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Ошибка хеширования пароля: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка сервера")
	}

	user := User{
		ID:           len(users) + 1,
		Login:        req.Login,
		PasswordHash: string(hashed),
	}
	users = append(users, user)

	return c.Status(fiber.StatusCreated).SendString("Регистрация успешна")
}

func login(c *fiber.Ctx) error {
	type Request struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	var req Request
	if err := c.BodyParser(&req); err != nil {
		fmt.Printf("Ошибка парсинга тела запроса: %v\n", err)
		return c.Status(fiber.StatusBadRequest).SendString("Неверный запрос")
	}

	var user User
	for _, u := range users {
		if u.Login == req.Login {
			user = u
			break
		}
	}

	if user.ID == 0 {
		return c.Status(fiber.StatusUnauthorized).SendString("Неверный логин или пароль")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Неверный логин или пароль")
	}

	sess, err := sessionStore.Get(c)
	if err != nil {
		fmt.Printf("Ошибка получения сессии: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка сессии")
	}
	sess.Set("userID", user.ID)
	if err := sess.Save(); err != nil {
		fmt.Printf("Ошибка сохранения сессии: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка сохранения сессии")
	}

	return c.Status(fiber.StatusOK).SendString("Вход успешен")
}

func profile(c *fiber.Ctx) error {
	sess, err := sessionStore.Get(c)
	if err != nil {
		fmt.Printf("Ошибка получения сессии: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка сессии")
	}
	userID, ok := sess.Get("userID").(int)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).SendString("Пользователь не авторизован")
	}

	var user User
	for _, u := range users {
		if u.ID == userID {
			user = u
			break
		}
	}

	if user.ID == 0 {
		return c.Status(fiber.StatusUnauthorized).SendString("Пользователь не найден")
	}

	return c.JSON(fiber.Map{"login": user.Login})
}

func logout(c *fiber.Ctx) error {
	sess, err := sessionStore.Get(c)
	if err != nil {
		fmt.Printf("Ошибка получения сессии: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка сессии")
	}
	if err := sess.Destroy(); err != nil {
		fmt.Printf("Ошибка удаления сессии: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка удаления сессии")
	}
	return c.Redirect("/", fiber.StatusFound)
}

func getData(c *fiber.Ctx) error {
	cacheDir := "./cache"
	cacheFile := filepath.Join(cacheDir, "data.txt")
	cacheDuration := time.Minute

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		fmt.Printf("Ошибка создания папки кэша: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка создания кэша")
	}

	if info, err := os.Stat(cacheFile); err == nil && time.Since(info.ModTime()) < cacheDuration {
		data, err := os.ReadFile(cacheFile)
		if err == nil {
			return c.Send(data)
		}
		fmt.Printf("Ошибка чтения кэша: %v\n", err)
	}

	data := []byte(fmt.Sprintf("Данные сгенерированы: %s", time.Now().UTC().Format(time.RFC3339)))
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		fmt.Printf("Ошибка записи кэша: %v\n", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Ошибка записи кэша")
	}

	return c.Send(data)
}
