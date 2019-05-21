package(default_visibility = ["//visibility:public"])

cc_binary(
    name = "app",
    copts = ["-DLOGGER_ENABLE"],
    srcs = ["cclient_app.c", "cclient_app.h",],
    deps = ["@entangled//cclient/api",
            "@entangled//utils:time",
            "@entangled//common/trinary:tryte_ascii",
            ],
    visibility = ["//visibility:public"],
)

cc_binary(
    name = "transaction_decoder",
    srcs = ["tools/transaction_decoder.c",],
    deps = ["@entangled//cclient/api",],
    visibility = ["//visibility:public"],
)
