package tenant

import "context"

type ID string

type ctxKey struct{}

func WithID(ctx context.Context, id ID) context.Context {
return context.WithValue(ctx, ctxKey{}, id)
}

func FromContext(ctx context.Context) (ID, bool) {
id, ok := ctx.Value(ctxKey{}).(ID)
return id, ok
}