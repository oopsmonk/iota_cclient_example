# local_repository(
#     name = "entangled",
#     path = "/path/to/entangled",
# )

git_repository(
    name = "entangled",
    commit = "ef8b9fb25f9833363c54523ce396a9c8966aa385",
    remote = "https://github.com/oopsmonk/entangled.git",
    # commit = "b57bd1fce59c8d9b6fcc2bcfbb960c0ef14ee261",
    # remote = "https://github.com/iotaledger/entangled.git",
)

git_repository(
    name = "rules_iota",
    commit = "39eeaf4fad15929b0fcc88b8fc473925a6bd9060",
    remote = "https://github.com/iotaledger/rules_iota.git",
)

load("@rules_iota//:defs.bzl", "iota_deps")

iota_deps()

