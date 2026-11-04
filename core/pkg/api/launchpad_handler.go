package api

import ()

type launchpadPlanRequest struct {
	AppID       string `json:"app_id"`
	SubstrateID string `json:"substrate_id"`
	Principal   string `json:"principal"`
}
