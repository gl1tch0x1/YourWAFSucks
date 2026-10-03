package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type Resource struct {
	ID       int    `json:"id"`
	OwnerID  int    `json:"owner_id"`
	Name     string `json:"name"`
	Content  string `json:"content"`
}

var users = []User{
	{ID: 1, Username: "user1", Role: "user"},
	{ID: 2, Username: "user2", Role: "user"},
	{ID: 3, Username: "admin", Role: "admin"},
}

var resources = []Resource{
	{ID: 1, OwnerID: 1, Name: "resource1", Content: "user1's resource"},
	{ID: 2, OwnerID: 2, Name: "resource2", Content: "user2's resource"},
	{ID: 3, OwnerID: 3, Name: "admin_resource", Content: "admin resource"},
}

func main() {
	http.HandleFunc("/api/users", getUsers)
	http.HandleFunc("/api/users/", getUser)
	http.HandleFunc("/api/resources", getResources)
	http.HandleFunc("/api/resources/", getResource)
	http.HandleFunc("/api/admin", adminOnly)
	http.HandleFunc("/health", health)

	fmt.Println("Starting authz test app on :8080")
	http.ListenAndServe(":8080", nil)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	if role == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	json.NewEncoder(w).Encode(users)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	role := r.Header.Get("X-Role")
	
	if role == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	for _, user := range users {
		if fmt.Sprintf("%d", user.ID) == id {
			// Horizontal authz: users can only see themselves
			if role == "user" && r.Header.Get("X-User-ID") != id {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
				return
			}
			json.NewEncoder(w).Encode(user)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
}

func getResources(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	if role == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	
	var userResources []Resource
	for _, res := range resources {
		// Users can only see their own resources
		if role == "user" && fmt.Sprintf("%d", res.OwnerID) == userID {
			userResources = append(userResources, res)
		}
		// Admins can see all resources
		if role == "admin" {
			userResources = append(userResources, res)
		}
	}

	json.NewEncoder(w).Encode(userResources)
}

func getResource(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/resources/")
	role := r.Header.Get("X-Role")
	userID := r.Header.Get("X-User-ID")
	
	if role == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	for _, res := range resources {
		if fmt.Sprintf("%d", res.ID) == id {
			// Horizontal authz: users can only access their own resources
			if role == "user" && fmt.Sprintf("%d", res.OwnerID) != userID {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
				return
			}
			json.NewEncoder(w).Encode(res)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
}

func adminOnly(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	
	if role != "admin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "admin area"})
}

func health(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}
