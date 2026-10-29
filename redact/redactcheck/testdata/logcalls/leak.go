package x

import (
	"strings"

	"github.com/interledger/cards-utils/redact"
)

type card struct{ PAN string }

func f(log Logger, c card, raw []byte) {
	log.Info().Interface("card", c).Msg("leak")
	log.Info().Any("card", c).Msg("leak")
	log.Info().Fields(map[string]any{"pan": c.PAN}).Msg("leak")
	log.Info().Object("card", c).Msg("leak")

	log.Info().Object("card", redact.Object(c)).Msg("ok")
	log.Info().Object("card", redact.AuditObject(c)).Msg("ok")
	log.Info().Object("card", redact.WithProfile(redact.ProfileAudit).Object(c)).Msg("ok")
	log.Info().Interface("card", redact.Redact(c)).Msg("ok")
	log.Info().RawJSON("body", redact.JSON(raw)).Msg("ok")
	_ = strings.Fields("not a log call")
}
