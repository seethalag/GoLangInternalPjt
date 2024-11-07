package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User struct represents the user document in MongoDB
type User struct {
    ID       primitive.ObjectID `bson:"_id,omitempty"`
    Username string             `bson:"username" validate:"required,min=3,max=32"`
    Password string             `bson:"password" validate:"required,min=6"`
     ResetToken     string             `bson:"reset_token,omitempty"`
    TokenExpiresAt time.Time          `bson:"token_expires_at,omitempty"`
}
