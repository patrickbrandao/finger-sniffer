//go:build !linux

package capture

import (
	"context"
	"errors"

	"github.com/patrickbrandao/finger-sniffer/pkg/service"
)

// Run só existe no Linux (AF_PACKET).
func Run(context.Context, *service.Service, Config) error {
	return errors.New("capture: AF_PACKET requires linux")
}
