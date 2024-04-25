package main

import (
	"context"
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

// Секретный ключ для подписи токена (Signature)
var jwtKey = []byte("goncharova_ekaterina")

func generateAccessToken(guid string) (string, time.Time, error) {
	// Создаем access токен. Валиден 5 минут, алгоритм - HS512 (основан на SHA512)
	accessTime := time.Now().Add(time.Minute * 5)

	accessToken := jwt.New(jwt.SigningMethodHS512)
	claims := accessToken.Claims.(jwt.MapClaims)
	claims["sub"] = guid
	claims["exp"] = accessTime.Unix()

	tokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		return "", accessTime, err
	}

	return tokenString, accessTime, nil
}

type RefreshSessions struct {
	User         string
	RefreshToken []byte
	ExpiresAt    time.Time
}

func generateRefreshToken(guid string) (string, time.Time, error) {
	// Создаем refresh токен. Валиден 24 часа
	accessTime := time.Now().Add(time.Hour * 24)

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		return "", accessTime, err
	}

	// Токен представляет собой uuid. Преобразуется в bcrypt-хеш перед сохранением в базу данных
	refreshTokenBytes := []byte(uuid.New().String())
	hashedRefreshToken, err := bcrypt.GenerateFromPassword(refreshTokenBytes, bcrypt.DefaultCost)

	if err != nil {
		return "", accessTime, err
	}

	coll := client.Database("auth_app").Collection("refresh_sessions")
	newSession := RefreshSessions{User: guid, RefreshToken: hashedRefreshToken, ExpiresAt: accessTime}
	_, err = coll.InsertOne(context.TODO(), newSession)

	if err != nil {
		return "", accessTime, err
	}

	// Токен передаем в кодировке base64
	return base64.StdEncoding.EncodeToString(refreshTokenBytes), accessTime, err
}

// Маршрут, выдающий пару токенов для пользователя с индентификатором, указанном в параметре запроса
func getTokenPair(w http.ResponseWriter, r *http.Request) {
	guid := r.FormValue("guid")

	if guid == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, accessTime, err := generateAccessToken(guid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	refreshToken, refreshAccessTime, err := generateRefreshToken(guid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	http.SetCookie(w,
		&http.Cookie{
			Name:     "token",
			Value:    token,
			Expires:  accessTime,
			HttpOnly: true,
		})

	http.SetCookie(w,
		&http.Cookie{
			Name:     "token",
			Value:    refreshToken,
			Expires:  refreshAccessTime,
			HttpOnly: true,
		})
}

func Refresh(w http.ResponseWriter, r *http.Request) {
}
