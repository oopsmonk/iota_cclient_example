# local_repository(
#     name = "entangled",
#     path = "/path/to/entangled",
# )

git_repository(
    name = "entangled",
    commit = "64633f5efa33a2be7fa1eca26a405b34be268794",
    remote = "https://github.com/oopsmonk/entangled.git",
)

git_repository(
    name = "rules_iota",
    commit = "b15744b9ea520717752c866d5afc769c3b6b68f3",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

load("@rules_iota//:defs.bzl", "iota_deps")

iota_deps()

