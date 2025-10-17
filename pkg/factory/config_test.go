package factory_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/pkg/factory"
)

func TestSnssaiInfoItem(t *testing.T) {
	testcase := []struct {
		Name     string
		Snssai   *models.Snssai
		DnnInfos []*factory.SnssaiDnnInfoItem
	}{
		{
			Name: "Default",
			Snssai: &models.Snssai{
				Sst: int32(1),
				Sd:  "010203",
			},
			DnnInfos: []*factory.SnssaiDnnInfoItem{
				{
					Dnn: "internet",
					DNS: &factory.DNS{
						IPv4Addr: "8.8.8.8",
					},
				},
			},
		},
		{
			Name: "Empty SD",
			Snssai: &models.Snssai{
				Sst: int32(1),
			},
			DnnInfos: []*factory.SnssaiDnnInfoItem{
				{
					Dnn: "internet2",
					DNS: &factory.DNS{
						IPv4Addr: "1.1.1.1",
					},
				},
			},
		},
	}

	for _, tc := range testcase {
		t.Run(tc.Name, func(t *testing.T) {
			snssaiInfoItem := factory.SnssaiInfoItem{
				SNssai:   tc.Snssai,
				DnnInfos: tc.DnnInfos,
			}

			ok, err := snssaiInfoItem.Validate()
			require.True(t, ok)
			require.Nil(t, err)
		})
	}
}

func TestSnssaiUpfInfoItem(t *testing.T) {
	testcase := []struct {
		Name     string
		Snssai   *models.Snssai
		DnnInfos []*factory.DnnUpfInfoItem
	}{
		{
			Name: "Default",
			Snssai: &models.Snssai{
				Sst: int32(1),
				Sd:  "010203",
			},
			DnnInfos: []*factory.DnnUpfInfoItem{
				{
					Dnn: "internet",
					PduSessionTypes: &models.PduSessionTypes{
						DefaultSessionType:  models.PduSessionType_IPV4,
						AllowedSessionTypes: []models.PduSessionType{models.PduSessionType_IPV4},
					},
					Pools: []*factory.UEIPPool{
						{Cidr: "10.60.0.0/16"},
					},
				},
			},
		},
		{
			Name: "Empty SD",
			Snssai: &models.Snssai{
				Sst: int32(1),
			},
			DnnInfos: []*factory.DnnUpfInfoItem{
				{
					Dnn: "internet2",
					PduSessionTypes: &models.PduSessionTypes{
						DefaultSessionType:  models.PduSessionType_IPV4_V6,
						AllowedSessionTypes: []models.PduSessionType{
							models.PduSessionType_IPV4,
							models.PduSessionType_IPV6,
							models.PduSessionType_IPV4_V6,
						},
					},
					Pools: []*factory.UEIPPool{
						{Cidr: "10.61.0.0/16"},
					},
					UeIPv6Pools: []*factory.UEIPv6Pool{
						{
							Prefix:         "2001:db8:61::/48",
							UePrefixLength: 64,
							IidAllocation:  "random",
						},
					},
				},
			},
		},
	}

	for _, tc := range testcase {
		t.Run(tc.Name, func(t *testing.T) {
			snssaiInfoItem := factory.SnssaiUpfInfoItem{
				SNssai:         tc.Snssai,
				DnnUpfInfoList: tc.DnnInfos,
			}

			ok, err := snssaiInfoItem.Validate()
			require.True(t, ok)
			require.Nil(t, err)
		})
	}
}
