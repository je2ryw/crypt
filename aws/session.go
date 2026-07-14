package aws

import (
	"context"

	"github.com/VirtusLab/go-extended/pkg/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

const (
	// DefaultProfile is the default profile to be used when loading configuration
	// from the config files if another profile name is not provided.
	DefaultProfile = "default"
)

// Config returns AWS API client config with given region and profile
func Config(ctx context.Context, region, profile string) (aws.Config, error) {
	// Environment variables can be also used, see: https://docs.aws.amazon.com/sdkref/latest/guide/settings-reference.html
	awsConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithSharedConfigProfile(profile),
	)

	return awsConfig, errors.Wrap(err)
}
