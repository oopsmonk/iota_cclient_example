#include "cclient_app.h"
#include <stdio.h>
#include <stdlib.h>

#define MY_SEED                                                                \
  "99999999999999999999999999999999999999999999999999999999999999999999999999" \
  "9999999"
#define MY_ADDR1                                                               \
  "99999999999999999999999999999999999999999999999999999999999999999999999999" \
  "9999999"
#define MY_ADDR2                                                               \
  "99999999999999999999999999999999999999999999999999999999999999999999999999" \
  "9999999"

/*#define HOST "nodes.devnet.iota.org"*/
/*#define PORT 80*/

#define HOST "localhost"
#define PORT 14265

void test_find_trans(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);

  retcode_t ret_code = RC_OK;
  flex_trit_t tmp_hash[FLEX_TRIT_SIZE_243];
  find_transactions_req_t *find_tran = find_transactions_req_new();

  ret_code = flex_trits_from_trytes(tmp_hash, NUM_TRITS_HASH,
                                    (const tryte_t *)MY_ADDR1, NUM_TRYTES_HASH,
                                    NUM_TRYTES_HASH);

  ret_code = hash243_queue_push(&find_tran->addresses, tmp_hash);
  if (ret_code) {
    goto err;
  }

  find_transactions_res_t *find_tran_res = find_transactions_res_new();
  ret_code = iota_client_find_transactions(s, find_tran, find_tran_res);

  char_buffer_t *tmp = char_buffer_new();

  if (ret_code == RC_OK) {
    size_t count = hash243_queue_count(&find_tran_res->hashes);
    hash243_queue_t curr = find_tran_res->hashes;
    tryte_t addr[NUM_TRYTES_HASH + 1];
    for (int i = 0; i < count; i++) {
      flex_trits_to_trytes(addr, NUM_TRYTES_HASH, curr->hash, NUM_TRITS_HASH,
                           NUM_TRITS_HASH);
      addr[NUM_TRYTES_HASH] = '\0';
      printf("[%d] %s\n", i, addr);
      curr = curr->next;
    }
  }

err:
  if (ret_code) {
    printf("find tx failed: %s\n", error_2_string(ret_code));
  }
  find_transactions_req_free(&find_tran);
  find_transactions_res_free(&find_tran_res);
  char_buffer_free(tmp);
}

void test_node_info(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  get_node_info_res_t *node_res = get_node_info_res_new();
  trit_t trytes_out[NUM_TRYTES_HASH + 1];
  size_t trits_count = 0;

  iota_client_get_node_info(s, node_res);

  printf("appName %s \n", node_res->app_name->data);
  printf("appVersion %s \n", node_res->app_version->data);
  printf("jreAvailableProcessors %d \n", node_res->jre_available_processors);
  printf("jreFreeMemory %zu \n", node_res->jre_free_memory);
  printf("jreMaxMemory %zu \n", node_res->jre_max_memory);
  printf("jreTotalMemory %zu \n", node_res->jre_total_memory);

  trits_count = flex_trits_to_trytes(trytes_out, NUM_TRYTES_HASH,
                                     node_res->latest_milestone, NUM_TRITS_HASH,
                                     NUM_TRITS_HASH);
  if (trits_count == 0) {
    printf("trit converting failed\n");
    return;
  }
  trytes_out[NUM_TRYTES_HASH] = '\0';
  printf("latestMilestone %s \n", trytes_out);

  printf("latestMilestoneIndex %zu \n", node_res->latest_milestone_index);

  trits_count = flex_trits_to_trytes(trytes_out, NUM_TRYTES_HASH,
                                     node_res->latest_milestone, NUM_TRITS_HASH,
                                     NUM_TRITS_HASH);
  if (trits_count == 0) {
    printf("trit converting failed\n");
    return;
  }
  trytes_out[NUM_TRYTES_HASH] = '\0';
  printf("latestSolidSubtangleMilestone %s \n", trytes_out);

  printf("latestSolidSubtangleMilestoneIndex %zu \n",
         node_res->latest_solid_subtangle_milestone_index);
  printf("neighbors %d \n", node_res->neighbors);
  printf("packetsQueueSize %d \n", node_res->packets_queue_size);
  printf("time %zu \n", node_res->time);
  printf("tips %d \n", node_res->tips);
  printf("transactionsToRequest %d \n", node_res->trans_to_request);

  get_node_info_res_free(&node_res);
}

void test_get_neighbors(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  get_neighbors_res_t *nbors_res = get_neighbors_res_new();

  retcode_t ret = iota_client_get_neighbors(s, nbors_res);
  if (ret != RC_OK) {
    printf("POST failed\n");
    get_neighbors_res_free(nbors_res);
    return;
  }
  neighbor_info_t *nb = get_neighbors_res_neighbor_at(nbors_res, 0);
  printf("addr %s\tall %d\tnew %d\tinvalid %d\n", nb->address->data,
         nb->all_trans_num, nb->new_trans_num, nb->invalid_trans_num);

  nb = get_neighbors_res_neighbor_at(nbors_res, 1);
  printf("addr %s\tall %d\tnew %d\tinvalid %d\n", nb->address->data,
         nb->all_trans_num, nb->new_trans_num, nb->invalid_trans_num);

  get_neighbors_res_dump(nbors_res);

  get_neighbors_res_free(nbors_res);
}

void test_add_neighbors(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  add_neighbors_req_t *add_req = add_neighbors_req_new();
  add_neighbors_res_t res = 0;
  add_neighbors_req_add(add_req, "udp://8.8.8.8:14265");
  add_neighbors_req_add(add_req, "udp://9.9.9.9:433");

  retcode_t ret = iota_client_add_neighbors(s, add_req, &res);
  if (ret != RC_OK) {
    printf("POST failed\n");
    return;
  }
  printf("res neighbors: %d\n", res);

  add_neighbors_req_free(add_req);
}

void test_remove_neighbors(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  remove_neighbors_req_t *remove_req = remove_neighbors_req_new();
  remove_neighbors_res_t res = 0;
  remove_neighbors_req_add(remove_req, "udp://8.8.8.8:14265");
  remove_neighbors_req_add(remove_req, "udp://9.9.9.9:433");

  retcode_t ret = iota_client_remove_neighbors(s, remove_req, &res);
  if (ret != RC_OK) {
    printf("POST failed\n");
    return;
  }
  printf("res neighbors: %d\n", res);

  remove_neighbors_req_free(remove_req);
}

void test_get_tips(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  get_tips_res_t *tips_res = get_tips_res_new();
  trit_t trytes_out[NUM_TRYTES_HASH + 1];
  size_t trits_count = 0;

  hash243_queue_entry_t *q_iter = NULL;

  iota_client_get_tips(s, tips_res);

  CDL_FOREACH(tips_res->hashes, q_iter) {
    trits_count =
        flex_trits_to_trytes(trytes_out, NUM_TRYTES_HASH, q_iter->hash,
                             NUM_TRITS_HASH, NUM_TRITS_HASH);
    trytes_out[NUM_TRYTES_HASH] = '\0';
    if (trits_count != 0) {
      printf("%s\n", trytes_out);
    }
  }

  get_tips_res_free(&tips_res);
}

void test_get_trytes(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  retcode_t ret_code = RC_OK;
  flex_trit_t tmp_hash[FLEX_TRIT_SIZE_243];
  size_t num_trytes = 0;
  trit_t trytes_out[NUM_TRYTES_SERIALIZED_TRANSACTION + 1];
  size_t trits_count = 0;
  hash8019_queue_entry_t *q_iter = NULL;
  get_trytes_req_t *trytes_req = get_trytes_req_new();
  get_trytes_res_t *trytes_res = get_trytes_res_new();

  num_trytes =
      flex_trits_from_trytes(tmp_hash, NUM_TRITS_HASH, (const tryte_t *)HASH_3,
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

  ret_code = iota_client_get_trytes(s, trytes_req, trytes_res);
  if (ret_code) {
    printf("Error: %s\n", error_2_string(ret_code));
    return;
  }

  CDL_FOREACH(trytes_res->trytes, q_iter) {
    trits_count = flex_trits_to_trytes(
        trytes_out, NUM_TRYTES_SERIALIZED_TRANSACTION, q_iter->hash,
        NUM_TRITS_SERIALIZED_TRANSACTION, NUM_TRITS_SERIALIZED_TRANSACTION);
    trytes_out[NUM_TRYTES_SERIALIZED_TRANSACTION] = '\0';
    if (trits_count != 0) {
      printf("%s\n", trytes_out);
    }
  }

  get_trytes_res_free(&trytes_res);
  get_trytes_req_free(&trytes_req);
}

void test_attach_to_tangle(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  attach_to_tangle_req_t *attach_req = attach_to_tangle_req_new();
  attach_to_tangle_res_t *attach_res = attach_to_tangle_res_new();
  flex_trit_t raw_trits[FLEX_TRIT_SIZE_8019];
  // for response
  hash8019_queue_entry_t *q_iter = NULL;
  trit_t trytes_out[NUM_TRYTES_SERIALIZED_TRANSACTION + 1];
  size_t trits_count = 0;

  flex_trits_from_trytes(attach_req->trunk, NUM_TRITS_HASH, HASH_1,
                         NUM_TRYTES_HASH, NUM_TRYTES_HASH);
  flex_trits_from_trytes(attach_req->branch, NUM_TRITS_HASH, HASH_2,
                         NUM_TRYTES_HASH, NUM_TRYTES_HASH);

  flex_trits_from_trytes(raw_trits, NUM_TRITS_SERIALIZED_TRANSACTION,
                         TRYRES_2673, NUM_TRYTES_SERIALIZED_TRANSACTION,
                         NUM_TRYTES_SERIALIZED_TRANSACTION);
  hash8019_queue_push(&attach_req->trytes, raw_trits);

  iota_client_attach_to_tangle(s, attach_req, attach_res);

  CDL_FOREACH(attach_res->trytes, q_iter) {
    trits_count = flex_trits_to_trytes(
        trytes_out, NUM_TRYTES_SERIALIZED_TRANSACTION, q_iter->hash,
        NUM_TRITS_SERIALIZED_TRANSACTION, NUM_TRITS_SERIALIZED_TRANSACTION);
    trytes_out[NUM_TRYTES_SERIALIZED_TRANSACTION] = '\0';
    if (trits_count != 0) {
      printf("%s\n", trytes_out);
    }
  }

  attach_to_tangle_res_free(&attach_res);
  attach_to_tangle_req_free(&attach_req);
}

void test_check_consistency(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  flex_trit_t trits_243[FLEX_TRIT_SIZE_243];
  check_consistency_req_t *consistency_req = check_consistency_req_new();
  check_consistency_res_t *consistency_res = check_consistency_res_new();

  flex_trits_from_trytes(trits_243, NUM_TRITS_HASH, HASH_3, NUM_TRYTES_HASH,
                         NUM_TRYTES_HASH);
  hash243_queue_push(&consistency_req->hashes, trits_243);

  iota_client_check_consistency(s, consistency_req, consistency_res);
  printf("%s\n", consistency_res->state ? "true" : "false");
  printf("%s\n", consistency_res->info->data);

  check_consistency_req_free(&consistency_req);
  check_consistency_res_free(consistency_res);
}

void test_get_inclustion(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  flex_trit_t trits_243[FLEX_TRIT_SIZE_243];
  size_t trits_len = 0;
  retcode_t ret_code = RC_OK;

  get_inclusion_state_req_t *get_inclustion_req = get_inclusion_state_req_new();
  get_inclusion_state_res_t *get_inclustion_res = get_inclusion_state_res_new();

  trits_len = flex_trits_from_trytes(trits_243, NUM_TRITS_HASH, HASH_1,
                                     NUM_TRYTES_HASH, NUM_TRYTES_HASH);
  if (trits_len) {
    ret_code = hash243_queue_push(&get_inclustion_req->hashes, trits_243);
    if (ret_code) {
      goto done;
    }
  }

  trits_len = flex_trits_from_trytes(trits_243, NUM_TRITS_HASH, HASH_2,
                                     NUM_TRYTES_HASH, NUM_TRYTES_HASH);
  if (trits_len) {
    ret_code = hash243_queue_push(&get_inclustion_req->tips, trits_243);
    if (ret_code) {
      goto done;
    }
  }

  if (iota_client_get_inclusion_states(s, get_inclustion_req,
                                       get_inclustion_res) == RC_OK) {
    for (int i = 0; i < get_inclusion_state_res_bool_num(get_inclustion_res);
         i++) {
      printf("[%d]:%s\n", i,
             get_inclusion_state_res_bool_at(get_inclustion_res, i) ? "true"
                                                                    : "false");
    }
  }

done:
  get_inclusion_state_req_free(&get_inclustion_req);
  get_inclusion_state_res_free(&get_inclustion_res);
}

void test_get_balance(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  retcode_t ret_code = RC_OK;
  flex_trit_t tmp_hash[FLEX_TRIT_SIZE_243];
  get_balances_req_t *balance_req = get_balances_req_new();
  get_balances_res_t *balance_res = get_balances_res_new();

  flex_trits_from_trytes(tmp_hash, NUM_TRITS_HASH, HASH_3, NUM_TRYTES_HASH,
                         NUM_TRYTES_HASH);
  ret_code = hash243_queue_push(&balance_req->addresses, tmp_hash);
  if (ret_code) {
    printf("Adding hash to list failed!\n");
    return;
  }

  balance_req->threshold = 100;

  if (iota_client_get_balances(s, balance_req, balance_res) == RC_OK) {
    trit_t trytes_out[NUM_TRYTES_HASH + 1];
    hash243_queue_entry_t *q_iter = NULL;
    size_t trits_count = 0;

    size_t balance_cnt = get_balances_res_balances_num(balance_res);
    printf("balances: [");
    for (int i = 0; i < balance_cnt; i++) {
      printf(" %ld ", get_balances_res_balances_at(balance_res, i));
    }
    printf("]\n");

    CDL_FOREACH(balance_res->milestone, q_iter) {
      trits_count =
          flex_trits_to_trytes(trytes_out, NUM_TRYTES_HASH, q_iter->hash,
                               NUM_TRITS_HASH, NUM_TRITS_HASH);
      trytes_out[NUM_TRYTES_HASH] = '\0';
      if (trits_count != 0) {
        printf("hash: %s\n", trytes_out);
      }
    }
  }

  get_balances_req_free(&balance_req);
  get_balances_res_free(&balance_res);
}

void test_tx_to_approve(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  trit_t trytes_out[NUM_TRYTES_HASH + 1];
  get_transactions_to_approve_req_t *tx_approve_req =
      get_transactions_to_approve_req_new();
  get_transactions_to_approve_res_t *tx_approve_res =
      get_transactions_to_approve_res_new();

  flex_trits_from_trytes(tx_approve_req->reference, NUM_TRITS_HASH, HASH_1,
                         NUM_TRYTES_HASH, NUM_TRYTES_HASH);
  tx_approve_req->depth = 14;

  if (iota_client_get_transactions_to_approve(s, tx_approve_req,
                                              tx_approve_res) == RC_OK) {
    flex_trits_to_trytes(trytes_out, NUM_TRYTES_HASH, tx_approve_res->trunk,
                         NUM_TRITS_HASH, NUM_TRITS_HASH);
    trytes_out[NUM_TRYTES_HASH] = '\0';
    printf("trunk: %s\n", trytes_out);

    flex_trits_to_trytes(trytes_out, NUM_TRYTES_HASH, tx_approve_res->branch,
                         NUM_TRITS_HASH, NUM_TRITS_HASH);
    trytes_out[NUM_TRYTES_HASH] = '\0';
    printf("branch: %s\n", trytes_out);
  }

  get_transactions_to_approve_req_free(&tx_approve_req);
  get_transactions_to_approve_res_free(&tx_approve_res);
}

void test_broadcast_tx(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  flex_trit_t tx_trits[FLEX_TRIT_SIZE_8019];
  broadcast_transactions_req_t *req = broadcast_transactions_req_new();

  flex_trits_from_trytes(tx_trits, NUM_TRITS_SERIALIZED_TRANSACTION,
                         TRYRES_2673, NUM_TRYTES_SERIALIZED_TRANSACTION,
                         NUM_TRYTES_SERIALIZED_TRANSACTION);

  hash8019_stack_push(&req->trytes, tx_trits);

  if (iota_client_broadcast_transactions(s, req)) {
    printf("broadcast_tx failed.\n");
  } else {
    printf("broadcast_tx done.\n");
  }
  broadcast_transactions_req_free(&req);
}

void test_store_tx(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  flex_trit_t tx_trits[FLEX_TRIT_SIZE_8019];
  store_transactions_req_t *req = store_transactions_req_new();

  flex_trits_from_trytes(tx_trits, NUM_TRITS_SERIALIZED_TRANSACTION,
                         TRYRES_2673, NUM_TRYTES_SERIALIZED_TRANSACTION,
                         NUM_TRYTES_SERIALIZED_TRANSACTION);

  hash8019_stack_push(&req->trytes, tx_trits);

  if (iota_client_store_transactions(s, req)) {
    printf("store_tx failed.\n");
  } else {
    printf("store_tx done.\n");
  }
  store_transactions_req_free(&req);
}

void test_get_new_address(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  retcode_t ret = RC_OK;
  flex_trit_t seed[FLEX_TRIT_SIZE_243];
  hash243_queue_t addresses = NULL;
  address_opt_t opt = {.security = 2, .start = 0, .total = 0};

  flex_trits_from_trytes(seed, NUM_TRITS_ADDRESS, (const tryte_t *)MY_SEED,
                         NUM_TRYTES_ADDRESS, NUM_TRYTES_ADDRESS);

  ret = iota_client_get_new_address(s, seed, opt, &addresses);
  if (ret == RC_OK) {
    size_t count = hash243_queue_count(&addresses);
    hash243_queue_t curr = addresses;
    tryte_t addr[NUM_TRYTES_ADDRESS + 1];
    for (int i = 0; i < count; i++) {
      flex_trits_to_trytes(addr, NUM_TRYTES_ADDRESS, curr->hash,
                           NUM_TRITS_ADDRESS, NUM_TRITS_ADDRESS);
      addr[NUM_TRYTES_ADDRESS] = '\0';
      printf("[%d] %s\n", i, addr);
      curr = curr->next;
    }
  } else {
    printf("new address failed: %s\n", error_2_string(ret));
  }
  hash243_queue_free(&addresses);
}

void test_get_inputs(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  retcode_t ret = RC_OK;
  flex_trit_t seed[FLEX_TRIT_SIZE_243];
  address_opt_t opt = {.security = 2, .start = 0, .total = 0};

  flex_trits_from_trytes(seed, NUM_TRITS_ADDRESS, (const tryte_t *)MY_SEED,
                         NUM_TRYTES_ADDRESS, NUM_TRYTES_ADDRESS);

  // new inputs
  inputs_t *inp = (inputs_t *)malloc(sizeof(inputs_t));
  inp->total_balance = 0;
  inp->addresses = NULL;

  ret = iota_client_get_inputs(s, seed, opt, 0, inp);
  if (ret) {
    printf("Error: %s\n", error_2_string(ret));
    return;
  }

  // printf result
  size_t addr_count = hash243_queue_count(&inp->addresses);
  printf("address count %zu\n", addr_count);
  for (int i = 0; i < addr_count; i++) {
    tryte_t trytes[NUM_TRYTES_ADDRESS + 1] = {[NUM_TRYTES_ADDRESS] = '\0'};
    flex_trits_to_trytes((signed char *)trytes, NUM_TRYTES_ADDRESS,
                         hash243_queue_at(&inp->addresses, i),
                         NUM_TRITS_ADDRESS, NUM_TRITS_ADDRESS);
    printf("[%d] %s\n", i, trytes);
  }

  printf("balances : %ld\n", inp->total_balance);

  // free inputs_t
  if (inp->addresses) {
    hash243_queue_free(&inp->addresses);
    inp->addresses = NULL;
  }
  free(inp);
}

void test_get_account_data(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  retcode_t ret = RC_OK;
  flex_trit_t seed[FLEX_TRIT_SIZE_243];

  flex_trits_from_trytes(seed, NUM_TRITS_ADDRESS, (const tryte_t *)MY_SEED,
                         NUM_TRYTES_ADDRESS, NUM_TRYTES_ADDRESS);

  // init account data
  account_data_t *account = (account_data_t *)malloc(sizeof(account_data_t));
  account->balance = 0;
  memset(account->latest_address, 0, NUM_TRYTES_ADDRESS * sizeof(trit_t));
  account->addresses = NULL;
  account->transactions = NULL;

  ret = iota_client_get_account_data(s, seed, 2, account);
  if (ret) {
    tryte_t trytes[NUM_TRYTES_ADDRESS + 1] = {[NUM_TRYTES_ADDRESS] = '\0'};
    // dump balance
    printf("total balance: %zu\n", account->balance);

    // dump unused address
    flex_trits_to_trytes((signed char *)trytes, NUM_TRYTES_ADDRESS,
                         account->latest_address, NUM_TRITS_ADDRESS,
                         NUM_TRITS_ADDRESS);
    printf("unused addr: %s\n", trytes);

    // dump addresses
    size_t addr_count = hash243_queue_count(&account->addresses);
    printf("address count %zu\n", addr_count);
    for (int i = 0; i < addr_count; i++) {
      flex_trits_to_trytes((signed char *)trytes, NUM_TRYTES_ADDRESS,
                           hash243_queue_at(&account->addresses, i),
                           NUM_TRITS_ADDRESS, NUM_TRITS_ADDRESS);
      printf("[%d] %s\n", i, trytes);
    }

    // dump tx
    size_t tx_count = hash243_queue_count(&account->transactions);
    printf("tx count %zu\n", tx_count);
    for (int i = 0; i < tx_count; i++) {
      flex_trits_to_trytes((signed char *)trytes, NUM_TRYTES_HASH,
                           hash243_queue_at(&account->transactions, i),
                           NUM_TRITS_HASH, NUM_TRITS_HASH);
      printf("[%d] %s\n", i, trytes);
    }

  } else {
    printf("Error: %s\n", error_2_string(ret));
    return;
  }
  hash243_queue_free(&account->transactions);
  hash243_queue_free(&account->addresses);
  free(account);
}

int main() {
  iota_client_service_t serv;
  serv.http.path = "/";
  serv.http.host = HOST;
  serv.http.port = PORT;
  serv.http.api_version = 1;
  serv.serializer_type = SR_JSON;
  logger_init();
  logger_output_register(stdout);
  logger_output_level_set(stdout, LOGGER_DEBUG);
  // logger_output_level_set(stdout, LOGGER_ERR);
  // logger_output_level_set(stdout, LOGGER_INFO);
  // logger_output_level_set(stdout, LOGGER_NOTICE);
  // logger_output_level_set(stdout, LOGGER_WARNING);
  iota_client_core_init(&serv);
  iota_client_extended_init();

#if 1
  // Core APIs
  test_find_trans(&serv);
  sleep(1);
  test_node_info(&serv);
  sleep(1);
  test_get_neighbors(&serv);
  sleep(1);
  test_add_neighbors(&serv);
  sleep(1);
  test_remove_neighbors(&serv);
  sleep(1);
  test_get_tips(&serv);
  sleep(1);
  test_get_trytes(&serv);
  sleep(1);
  test_attach_to_tangle(&serv);
  sleep(1);
  test_check_consistency(&serv);
  sleep(1);
  test_get_inclustion(&serv);
  sleep(1);
  test_get_balance(&serv);
  sleep(1);
  test_tx_to_approve(&serv);
  sleep(1);
  test_broadcast_tx(&serv);
  sleep(1);
  test_store_tx(&serv);
#endif

#if 0
  // extended APIs
  test_get_new_address(&serv); sleep(1);
  test_get_inputs(&serv); sleep(1);
  test_get_account_data(&serv); sleep(1);
#endif

  iota_client_extended_destroy();
  iota_client_core_destroy(&serv);
  return 0;
}
