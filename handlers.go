package main

import (
	"context"
	"encoding/base64"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

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
			Name:     "refresh_token",
			Value:    refreshToken,
			Expires:  refreshAccessTime,
			HttpOnly: true,
		})
}

func refresh(w http.ResponseWriter, r *http.Request) {
	encodedRefreshToken, err := r.Cookie("refresh_token")

	// Если рефреш токена нет (если он истек, то тоже исчезает из кук), то надо авторизовываться заново
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Декодируем токен из base64 обратно в список байтов.
	// Перебираем каждую запись в базе данных для сравнения хеша
	decodedRefreshToken, err := base64.StdEncoding.DecodeString(encodedRefreshToken.Value)

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	coll := client.Database("auth_app").Collection("refresh_sessions")

	cursor, err := coll.Find(context.TODO(), bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(context.TODO())

	// Получаем айди пользователя из найденной сессии
	var userGuid string

	for cursor.Next(context.TODO()) {
		var session bson.M
		if err := cursor.Decode(&session); err != nil {
			log.Fatal(err)
		}

		token := session["refreshToken"].(primitive.Binary).Data

		if err := bcrypt.CompareHashAndPassword(token, decodedRefreshToken); err == nil {
			userGuid = session["user"].(string)
			break
		}
	}

	if userGuid == "" {
		w.WriteHeader(http.StatusInternalServerError)
	}

	// Удаляем прошлую рефреш-сессию из базы данных
	filter := bson.M{"user": userGuid}
	_, err = coll.DeleteOne(context.TODO(), filter)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	// Используем найденный uuid для генерации новых токенов
	token, accessTime, err := generateAccessToken(userGuid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	refreshToken, refreshAccessTime, err := generateRefreshToken(userGuid)
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
			Name:     "refresh_token",
			Value:    refreshToken,
			Expires:  refreshAccessTime,
			HttpOnly: true,
		})

	defer func(client *mongo.Client, ctx context.Context) {
		err := client.Disconnect(ctx)
		if err != nil {
			return
		}
	}(client, context.TODO())
}
