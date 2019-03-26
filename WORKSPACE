# local_repository(
#     name = "entangled",
#     path = "/path/to/entangled",
# )

git_repository(
    name = "entangled",
    commit = "f0ab6522942ff02bc95f84d37ca1bd2a0a267dfe",
    remote = "https://github.com/iotaledger/entangled.git",
)

git_repository(
    name = "rules_iota",
    commit = "1cb59eea62fd1d071de213a9aa46e61e8273472d",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

load("@rules_iota//:defs.bzl", "iota_deps")

iota_deps()

