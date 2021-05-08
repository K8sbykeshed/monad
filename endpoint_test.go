package monad

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDummyEndpoint(t *testing.T) {
	assert := assert.New(t)

	ep := &dummyEndpoint{}
	epStr, err := ep.String(dummyFmt)
	assert.Empty(epStr)
	assert.Error(err)
	assert.Empty(ep.Contains(ep))
}
