"""v2 of the clean control, for `sniff-test diff` tests: same code plus a secrets read
and an undeclared host (const.STATUS). Never executed."""


def load_overrides(hass):
    with open(hass.config.path("secrets.yaml"), encoding="utf-8") as fh:
        return fh.read()
