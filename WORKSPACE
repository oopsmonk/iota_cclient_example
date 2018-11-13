# local_repository(
#     name = "entangled",
#     path = "/path/to/entangled",
# )

git_repository(
    name = "entangled",
    commit = "08f6a1be4deb4b323f23a53aac94de8432d9a46b",
    remote = "https://github.com/oopsmonk/entangled.git",
    # commit = "b57bd1fce59c8d9b6fcc2bcfbb960c0ef14ee261",
    # remote = "https://github.com/iotaledger/entangled.git",
)

git_repository(
    name = "rules_iota",
    commit = "893bc942f22aa6ad5bbd72e7d86c94452fbd76d8",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

load("@rules_iota//:defs.bzl", "iota_deps")

iota_deps()

