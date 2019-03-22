package libzec_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLibZEC(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "LibZEC Suite")
}
