/*
@author: @Panharoth06
@date: 2026-04-03
@description: Context helpers for propagating user identity via gRPC metadata
*/

package interceptor

import (
	"context"

	"google.golang.org/grpc/metadata"
)

const (
	userIDMetadataKey     = "x-user-id"
	apiKeyIDMetadataKey   = "x-api-key-id"
	apiProjectMetadataKey = "x-api-project-id"
)

type userIDKey struct{}
type apiKeyIDKey struct{}
type apiProjectIDKey struct{}

// InjectIdentity extracts request identity metadata and attaches it to the context.
func InjectIdentity(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	if vals := md.Get(userIDMetadataKey); len(vals) > 0 {
		ctx = context.WithValue(ctx, userIDKey{}, vals[0])
	}
	if vals := md.Get(apiKeyIDMetadataKey); len(vals) > 0 {
		ctx = context.WithValue(ctx, apiKeyIDKey{}, vals[0])
	}
	if vals := md.Get(apiProjectMetadataKey); len(vals) > 0 {
		ctx = context.WithValue(ctx, apiProjectIDKey{}, vals[0])
	}
	return ctx
}

// GetUserID retrieves the user ID from the context.
func GetUserID(ctx context.Context) (string, bool) {
	val := ctx.Value(userIDKey{})
	if val == nil {
		return "", false
	}
	userID, ok := val.(string)
	return userID, ok
}

// MustGetUserID retrieves the user ID from the context, panicking if not set.
func MustGetUserID(ctx context.Context) string {
	userID, ok := GetUserID(ctx)
	if !ok {
		panic("user_id not found in context — ensure the InjectUserID interceptor is registered")
	}
	return userID
}

// RequireUserID retrieves the user ID from the context, returning an error if missing.
func RequireUserID(ctx context.Context) (string, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return "", ErrUnauthenticated
	}
	return userID, nil
}

func GetAPIKeyID(ctx context.Context) (string, bool) {
	val := ctx.Value(apiKeyIDKey{})
	if val == nil {
		return "", false
	}
	apiKeyID, ok := val.(string)
	return apiKeyID, ok
}

func GetAPIProjectID(ctx context.Context) (string, bool) {
	val := ctx.Value(apiProjectIDKey{})
	if val == nil {
		return "", false
	}
	projectID, ok := val.(string)
	return projectID, ok
}
