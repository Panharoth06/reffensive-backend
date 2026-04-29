/*
@author: @Panharoth06
@date: 2026-04-03
@description: Errors for the interceptor package
*/

package interceptor

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrUnauthenticated = status.Error(codes.Unauthenticated, "unauthenticated: user identity not found in request context")

// IsUnauthenticated checks if the error is an unauthenticated error.
func IsUnauthenticated(err error) bool {
	return errors.Is(err, ErrUnauthenticated) || status.Code(err) == codes.Unauthenticated
}
