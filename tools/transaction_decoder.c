#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "cclient/api/core/core_api.h"

#define DEFAULT_HOST "nodes.devnet.iota.org"
#define DEFAULT_PORT 80
static iota_client_service_t g_client;

void tx_obj_dump(iota_transaction_t* tx_obj) {
  tryte_t trytes_81[NUM_TRYTES_HASH + 1];
  tryte_t trytes_27[NUM_TRYTES_TAG + 1];

  printf("==========Transaction Object==========\n");
  // address
  flex_trits_to_trytes(trytes_81, NUM_TRYTES_HASH, transaction_address(tx_obj),
                       NUM_TRITS_HASH, NUM_TRITS_HASH);
  trytes_81[NUM_TRYTES_HASH] = '\0';
  printf("addr: %s\n", trytes_81);

  printf("value: %" PRId64 "\n", transaction_value(tx_obj));

  flex_trits_to_trytes(trytes_81, NUM_TRYTES_HASH,
                       transaction_obsolete_tag(tx_obj), NUM_TRITS_HASH,
                       NUM_TRITS_HASH);
  trytes_81[NUM_TRYTES_HASH] = '\0';
  printf("obsolete_tag: %s\n", trytes_81);

  printf("timestamp: %" PRId64 "\n", transaction_timestamp(tx_obj));
  printf("curr index: %" PRId64 " \nlast index: %" PRId64 "\n",
         transaction_current_index(tx_obj), transaction_last_index(tx_obj));

  flex_trits_to_trytes(trytes_81, NUM_TRYTES_HASH, transaction_bundle(tx_obj),
                       NUM_TRITS_HASH, NUM_TRITS_HASH);
  trytes_81[NUM_TRYTES_HASH] = '\0';
  printf("bundle: %s\n", trytes_81);

  flex_trits_to_trytes(trytes_81, NUM_TRYTES_HASH, transaction_trunk(tx_obj),
                       NUM_TRITS_HASH, NUM_TRITS_HASH);
  trytes_81[NUM_TRYTES_HASH] = '\0';
  printf("trunk: %s\n", trytes_81);

  flex_trits_to_trytes(trytes_81, NUM_TRYTES_HASH, transaction_branch(tx_obj),
                       NUM_TRITS_HASH, NUM_TRITS_HASH);
  trytes_81[NUM_TRYTES_HASH] = '\0';
  printf("branch: %s\n", trytes_81);

  flex_trits_to_trytes(trytes_27, NUM_TRYTES_TAG, transaction_tag(tx_obj),
                       NUM_TRITS_TAG, NUM_TRITS_TAG);
  trytes_27[NUM_TRYTES_TAG] = '\0';
  printf("tag: %s\n", trytes_27);

  printf("attachment_timestamp: %" PRId64 "\n",
         transaction_attachment_timestamp(tx_obj));
  printf("attachment_timestamp_lower: %" PRId64 "\n",
         transaction_attachment_timestamp_lower(tx_obj));
  printf("attachment_timestamp_upper: %" PRId64 "\n",
         transaction_attachment_timestamp_upper(tx_obj));

  flex_trits_to_trytes(trytes_27, NUM_TRYTES_TAG, transaction_nonce(tx_obj),
                       NUM_TRITS_TAG, NUM_TRITS_TAG);
  trytes_27[NUM_TRYTES_TAG] = '\0';
  printf("nonce: %s\n", trytes_27);

  flex_trits_to_trytes(trytes_81, NUM_TRYTES_HASH, transaction_hash(tx_obj),
                       NUM_TRITS_HASH, NUM_TRITS_HASH);
  trytes_81[NUM_TRYTES_HASH] = '\0';
  printf("hash: %s\n", trytes_81);
}

void tx_trytes_dump(const char *char_tx) {
  flex_trit_t flex_tx[FLEX_TRIT_SIZE_8019] = {};
  iota_transaction_t* tx_obj = NULL;

  flex_trits_from_trytes(
      flex_tx, NUM_TRITS_SERIALIZED_TRANSACTION, (const tryte_t *)char_tx,
      NUM_TRYTES_SERIALIZED_TRANSACTION, NUM_TRYTES_SERIALIZED_TRANSACTION);

  tx_obj = transaction_deserialize(flex_tx, true);
  tx_obj_dump(tx_obj);
}

void transaction_get_trytes(iota_client_service_t *serv, char const *const tx) {
  retcode_t ret_code = RC_OK;
  iota_transaction_t* tx_obj = NULL;
  flex_trit_t tmp_hash[FLEX_TRIT_SIZE_243];
  size_t num_trytes = 0;
  hash8019_queue_entry_t *q_iter = NULL;
  get_trytes_req_t *trytes_req = get_trytes_req_new();
  get_trytes_res_t *trytes_res = get_trytes_res_new();

  num_trytes =
      flex_trits_from_trytes(tmp_hash, NUM_TRITS_HASH, (const tryte_t *)tx,
                             NUM_TRYTES_HASH, NUM_TRYTES_HASH);
  if (num_trytes == 0) {
    printf("trit converting failed\n");
    return;
  }

  ret_code = hash243_queue_push(&trytes_req->hashes, tmp_hash);
  if (ret_code) {
    printf("Error: %s\n", error_2_string(ret_code));
    return;
  }

  ret_code = iota_client_get_trytes(serv, trytes_req, trytes_res);
  if (ret_code) {
    printf("Error: %s\n", error_2_string(ret_code));
    return;
  }

  CDL_FOREACH(trytes_res->trytes, q_iter) {
    tx_obj = transaction_deserialize(q_iter->hash, true);
    tx_obj_dump(tx_obj);
  }

  get_trytes_res_free(&trytes_res);
  get_trytes_req_free(&trytes_req);
}

void usage(const char* app_name){
  printf("%s RAW_TRANSACTION\n", app_name);
  printf("%s TRANSACTION_HASH\n", app_name);
  printf("%s -h HOST -p PORT TRANSACTION_HASH\n", app_name);
}

int main(int argc, char *argv[]) {
  int opt;
  if(argc < 2){
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  while ((opt = getopt(argc, argv, "h:p:")) != -1) {
    switch (opt) {
      case 'h':
        // set host
        g_client.http.host = optarg;
        break;
      case 'p':
        // set port
        g_client.http.port = atoi(optarg);
        break;
      default:
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  // validate options
  if (g_client.http.host == NULL) {
    g_client.http.host = DEFAULT_HOST;
  }

  if (g_client.http.port == 0) {
    g_client.http.port = DEFAULT_PORT;
  }

  g_client.http.path = "/";
  g_client.http.content_type = "application/json";
  g_client.http.accept = "application/json";
  g_client.http.api_version = 1;
  g_client.serializer_type = SR_JSON;
  logger_init();
  logger_output_register(stdout);
  logger_output_level_set(stdout, LOGGER_DEBUG);
  iota_client_core_init(&g_client);

  for (int i = optind; i < argc; i++) {
    size_t trytes_len = strlen(argv[i]);
    if (trytes_len == NUM_TRYTES_SERIALIZED_TRANSACTION) {
      tx_trytes_dump(argv[i]);
    } else if (trytes_len == NUM_TRYTES_HASH) {
      printf("Connect to %s:%zu\n", g_client.http.host, g_client.http.port);
      transaction_get_trytes(&g_client, argv[i]);
    } else {
      printf("wrong transaction length\n");
    }
  }

  iota_client_core_destroy(&g_client);
  exit(EXIT_SUCCESS);
}

