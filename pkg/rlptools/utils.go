package rlptools

import (
	"fmt"

	limitadorv1alpha1 "github.com/kuadrant/limitador-operator/api/v1alpha1"

	kuadrantv1beta2 "github.com/kuadrant/kuadrant-operator/api/v1beta2"
	"github.com/kuadrant/kuadrant-operator/pkg/library/utils"
	"github.com/kuadrant/kuadrant-operator/pkg/rlptools/wasm"
)

// LimitadorRateLimitsFromRLP converts rate limits from a Kuadrant RateLimitPolicy into a list of Limitador rate limit
// objects
func LimitadorRateLimitsFromRLP(rlp *kuadrantv1beta2.RateLimitPolicy) []limitadorv1alpha1.RateLimit {
	limitsNamespace := wasm.LimitsNamespaceFromRLP(rlp)

	rateLimits := make([]limitadorv1alpha1.RateLimit, 0)
	for limitKey, limit := range rlp.Spec.CommonSpec().Limits {
		limitIdentifier := wasm.LimitNameToLimitadorIdentifier(limitKey)
		for _, rate := range limit.Rates {
			maxValue, seconds := rateToSeconds(rate)
			rateLimits = append(rateLimits, limitadorv1alpha1.RateLimit{
				Namespace:  limitsNamespace,
				MaxValue:   maxValue,
				Seconds:    seconds,
				Conditions: []string{fmt.Sprintf("%s == \"1\"", limitIdentifier)},
				Variables:  utils.GetEmptySliceIfNil(limit.CountersAsStringList()),
				Name:       LimitsNameFromRLP(rlp),
			})
		}
	}
	return rateLimits
}

func LimitsNameFromRLP(rlp *kuadrantv1beta2.RateLimitPolicy) string {
	return wasm.LimitsNamespaceFromRLP(rlp)
}

var timeUnitMap = map[kuadrantv1beta2.TimeUnit]int{
	kuadrantv1beta2.TimeUnit("second"): 1,
	kuadrantv1beta2.TimeUnit("minute"): 60,
	kuadrantv1beta2.TimeUnit("hour"):   60 * 60,
	kuadrantv1beta2.TimeUnit("day"):    60 * 60 * 24,
}

// rateToSeconds converts from RLP Rate API (limit, duration and unit)
// to Limitador's Limit format (maxValue, Seconds)
func rateToSeconds(rate kuadrantv1beta2.Rate) (maxValue int, seconds int) {
	maxValue = rate.Limit
	seconds = 0

	if tmpSecs, ok := timeUnitMap[rate.Unit]; ok && rate.Duration > 0 {
		seconds = tmpSecs * rate.Duration
	}

	if rate.Duration < 0 {
		seconds = 0
	}

	if rate.Limit < 0 {
		maxValue = 0
	}

	return
}
