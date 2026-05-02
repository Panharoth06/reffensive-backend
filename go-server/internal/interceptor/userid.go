/*
@author: @Panharoth06
@date: 2026-04-03
@description: gRPC server interceptor that injects user identity from metadata into context
*/

package interceptor

import (
	"context"

	"google.golang.org/grpc"
)

// UserIDUnaryInterceptor is a unary server interceptor that extracts user ID
// from gRPC metadata and injects it into the context.
func UserIDUnaryInterceptor(
	ctx context.Context,
	req interface{},
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	ctx = InjectIdentity(ctx)
	return handler(ctx, req)
}

// UserIDStreamInterceptor is a stream server interceptor that does the same for streaming RPCs.
func UserIDStreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	_ *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	wrapped := &wrappedServerStream{ServerStream: ss}
	wrapped.ctx = InjectIdentity(ss.Context())
	return handler(srv, wrapped)
}

// wrappedServerStream wraps a ServerStream so that Context() returns the enriched context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// ChainUnaryServer creates a single unary interceptor that chains multiple interceptors.
func ChainUnaryServer(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		build := func(current grpc.UnaryHandler, next grpc.UnaryServerInterceptor) grpc.UnaryHandler {
			return func(currentCtx context.Context, currentReq interface{}) (interface{}, error) {
				return next(currentCtx, currentReq, info, current)
			}
		}

		chain := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			chain = build(chain, interceptors[i])
		}

		return chain(ctx, req)
	}
}
