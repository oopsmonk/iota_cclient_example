package(default_visibility = ["//visibility:public"])

cc_binary(
    name = "app",
    copts = ["-DLOGGER_ENABLE"],
    srcs = ["cclient_app.c", "cclient_app.h",],
    includes = ["external/entangled/cclient/"],
    deps = ["@entangled//cclient:api",],
    visibility = ["//visibility:public"],
)

