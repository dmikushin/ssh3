//go:build !linux

package netchange

// New on non-Linux platforms returns ErrUnsupported.  A real watcher
// would require platform-specific code (route monitor sockets on macOS
// / BSD, NotifyAddrChange / NotifyRouteChange on Windows) which we do
// not implement here.  Callers should treat ErrUnsupported as a soft
// failure: QUIC path migration still works, it just won't be nudged by
// OS notifications.
func New() (Watcher, error) {
	return nil, ErrUnsupported
}
