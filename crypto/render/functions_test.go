package render

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTemplateFunctionsIncludesOCI(t *testing.T) {
	functions := TemplateFunctions()

	assert.Contains(t, functions, "encryptOCI")
	assert.Contains(t, functions, "decryptOCI")
}
