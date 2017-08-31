package auth

import (
	"net/http"

	"github.com/concourse/atc"
	"github.com/concourse/atc/db"
)

// AutomaticTeamCreationWrapper will have the side-effect of
// creating a team, if:
//     1. IsAuthenticated() returns true
// and 2. the team returned by GetTeam() does not exist
type AutomaticTeamCreationWrapper struct {
	// Validator to wrap
	Validator ValidatingUserContextReader

	// TeamFactory to check existence of teams, and create in if needed
	TeamFactory db.TeamFactory

	// TeamCreator is a function that should return an appropriately configured Team object to store.
	// If an error is returned, the object is not attepted to be stored.
	TeamCreator func(teamName string) (*atc.Team, error)
}

func (a *AutomaticTeamCreationWrapper) IsAuthenticated(r *http.Request) bool {
	authenticated := a.Validator.IsAuthenticated(r)

	// Don't do anything unless we're authenticated
	if !authenticated {
		return false
	}

	teamName, _, _ := a.GetTeam(r)
	if teamName == "" {
		// doesn't make sense for us to try to create anything
		return true
	}

	_, found, err := a.TeamFactory.FindTeam(teamName)
	if err != nil {
		// no point continuing
		return false
	}

	if found {
		// no work required
		return true
	}

	// We need to create a team

	// Callback to create appropriate config
	teamConfig, err := a.TeamCreator(teamName)
	if err != nil {
		// no point continuing
		return false
	}

	_, err = a.TeamFactory.CreateTeam(*teamConfig)
	if err != nil {
		// no point continuing
		return false
	}

	return true
}

func (a *AutomaticTeamCreationWrapper) GetTeam(r *http.Request) (string, bool, bool) {
	return a.Validator.GetTeam(r)
}

func (a *AutomaticTeamCreationWrapper) GetSystem(r *http.Request) (bool, bool) {
	return a.Validator.GetSystem(r)
}

func (a *AutomaticTeamCreationWrapper) GetCSRFToken(r *http.Request) (string, bool) {
	return a.Validator.GetCSRFToken(r)
}
