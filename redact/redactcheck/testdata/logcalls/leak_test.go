package x

func g(log Logger, c card) {
	log.Info().Interface("card", c).Msg("tests are not scanned")
}
