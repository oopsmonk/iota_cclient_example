#include "cclient_app.h"
#include <stdio.h>
#include <stdlib.h>

void test_find_trans(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);

  find_transactions_req_t *find_tran = find_transactions_req_new();
  find_tran = find_transactions_req_add_address(find_tran, HASH_1);
  find_tran = find_transactions_req_add_address(find_tran, HASH_2);

  find_transactions_res_t *find_tran_res = find_transactions_res_new();
  iota_client_find_transactions(s, find_tran, &find_tran_res);

  printf("address num = %d\n", find_transactions_res_hash_num(find_tran_res));
  char_buffer_t *hash1 = char_buffer_new();
  flex_hash_to_char_buffer(find_transactions_res_hash_at(find_tran_res, 0), hash1);

  char_buffer_t *hash2 = char_buffer_new();
  flex_hash_to_char_buffer(find_transactions_res_hash_at(find_tran_res, 1), hash2);

  printf("0: %s\n", hash1->data);
  printf("1: %s\n", hash2->data);

  find_transactions_req_free(&find_tran);
  find_transactions_res_free(find_tran_res);
  char_buffer_free(hash1);
  char_buffer_free(hash2);
}

void test_node_info(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  get_node_info_res_t *node_res = get_node_info_res_new();

  iota_client_get_node_info(s, &node_res);

  printf("appName %s \n", node_res->app_name->data);
  printf("appVersion %s \n", node_res->app_version->data);
  printf("jreAvailableProcessors %d \n", node_res->jre_available_processors);
  printf("jreFreeMemory %zu \n", node_res->jre_free_memory);
  printf("jreMaxMemory %zu \n", node_res->jre_max_memory);
  printf("jreTotalMemory %zu \n", node_res->jre_total_memory);

  char_buffer_t *last_m = char_buffer_new();
  flex_hash_to_char_buffer(node_res->latest_milestone, last_m);
  printf("latestMilestone %s \n", last_m->data);

  printf("latestMilestoneIndex %zu \n", node_res->latest_milestone_index);

  char_buffer_t *last_ssm = char_buffer_new();
  flex_hash_to_char_buffer(node_res->latest_solid_subtangle_milestone, last_ssm);
  printf("latestSolidSubtangleMilestone %s \n", last_ssm->data);

  printf("latestSolidSubtangleMilestoneIndex %zu \n",
         node_res->latest_solid_subtangle_milestone_index);
  printf("neighbors %d \n", node_res->neighbors);
  printf("packetsQueueSize %d \n", node_res->packets_queue_size);
  printf("time %zu \n", node_res->time);
  printf("tips %d \n", node_res->tips);
  printf("transactionsToRequest %d \n", node_res->trans_to_request);

  get_node_info_res_free(&node_res);
  char_buffer_free(last_m);
  char_buffer_free(last_ssm);
}

void test_get_neighbors(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  get_neighbors_res_t *nbors_res = get_neighbors_res_new();

  retcode_t ret = iota_client_get_neighbors(s, nbors_res);
  if (ret != RC_OK) {
    printf("POST failed\n");
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

  iota_client_get_tips(s, &tips_res);
  for (int i = 0; i < get_tips_res_hash_num(tips_res); i++) {
    char_buffer_t *t = char_buffer_new();
    flex_hash_to_char_buffer(get_tips_res_hash_at(tips_res, i), t);
    printf("%s\n", t->data);
    char_buffer_free(t);
  }

  get_tips_res_free(tips_res);
}

void test_get_trytes(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  get_trytes_req_t *trytes_req = get_trytes_req_new();
  get_trytes_res_t *trytes_res = get_trytes_res_new();
  trytes_req = get_trytes_req_add(trytes_req, HASH_3);

  iota_client_get_trytes(s, trytes_req, &trytes_res);
  for (int i = 0; i < get_trytes_res_num(trytes_res); i++) {
    char_buffer_t *t = char_buffer_new();
    flex_hash_to_char_buffer(get_trytes_res_at(trytes_res, i), t);
    printf("%s\n", t->data);
    char_buffer_free(t);
  }

  get_trytes_res_free(trytes_res);
  get_trytes_req_free(trytes_req);
}

void test_attach_to_tangle(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  attach_to_tangle_req_t *attach_req = attach_to_tangle_req_new();
  attach_to_tangle_res_t *attach_res = attach_to_tangle_res_new();

  attach_to_tangle_req_set_trunk(attach_req, HASH_1);
  attach_to_tangle_req_set_branch(attach_req, HASH_2);
  attach_req->trytes =
      attach_to_tangle_req_add_trytes(attach_req->trytes, "WHATEVER");

  iota_client_attach_to_tangle(s, attach_req, &attach_res);
  for (int i = 0; i < attach_to_tangle_res_trytes_cnt(attach_res); i++) {
    char_buffer_t *t = char_buffer_new();
    flex_hash_to_char_buffer(get_trytes_res_at(attach_res, i), t);
    printf("%s\n", t->data);
    char_buffer_free(t);
  }

  attach_to_tangle_res_free(attach_res);
  attach_to_tangle_req_free(&attach_req);
}

void test_check_consistency(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  check_consistency_req_t *consistency_req = check_consistency_req_new();
  check_consistency_res_t *consistency_res = check_consistency_res_new();
  consistency_req = check_consistency_req_add(consistency_req, HASH_3);

  iota_client_check_consistency(s, consistency_req, consistency_res);
  printf("%s\n", consistency_res->state ? "true" : "false");
  printf("%s\n", consistency_res->info->data);

  check_consistency_res_free(consistency_res);
  check_consistency_req_free(consistency_req);
}

void test_get_inclustion(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);

  get_inclusion_state_req_t *get_inclustion_req = get_inclusion_state_req_new();
  get_inclusion_state_res_t *get_inclustion_res = get_inclusion_state_res_new();

  get_inclustion_req =
      get_inclusion_state_req_add_hash(get_inclustion_req, HASH_1);
  get_inclustion_req =
      get_inclusion_state_req_add_tip(get_inclustion_req, HASH_2);

  if (iota_client_get_inclusion_states(s, get_inclustion_req,
                                    get_inclustion_res) == RC_OK) {
    for (int i = 0; i < get_inclusion_state_res_bool_num(get_inclustion_res); i++) {
      printf("[%d]:%s\n", i, get_inclusion_state_res_bool_at(get_inclustion_res, i) ? "true" : "false");
    }
  }

  get_inclusion_state_req_free(&get_inclustion_req);
  get_inclusion_state_res_free(&get_inclustion_res);
}

void test_get_balance(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  trit_array_p tmp_ref = NULL;
  char_buffer_t *hash_txt = char_buffer_new();
  get_balances_req_t *balance_req = get_balances_req_new();
  get_balances_res_t *balance_res = get_balances_res_new();

  balance_req = get_balances_req_add_address(balance_req, HASH_3);
  balance_req->threshold = 0;
  if (iota_client_get_balances(s, balance_req, &balance_res) == RC_OK) {
    printf("balance0: %s\n", get_balances_res_balances_at(balance_res, 0));
    printf("balance1: %s\n", get_balances_res_balances_at(balance_res, 1));
    printf("balance2: %s\n", get_balances_res_balances_at(balance_res, 2));
    tmp_ref = get_balances_res_milestone_at(balance_res, 0);
    flex_hash_to_char_buffer(tmp_ref, hash_txt);
    printf("hash: %s\n", hash_txt->data);
  }
  get_balances_req_free(&balance_req);
  get_balances_res_free(balance_res);
  char_buffer_free(hash_txt);
}

void test_tx_to_approve(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  char_buffer_t *hash_txt = char_buffer_new();
  get_transactions_to_approve_req_t *tx_approve_req =
      get_transactions_to_approve_req_new();
  get_transactions_to_approve_res_t *tx_approve_res =
      get_transactions_to_approve_res_new();

  get_transactions_to_approve_req_set_reference(tx_approve_req, HASH_1);
  tx_approve_req->depth = 14;
  if (iota_client_get_transactions_to_approve(s, tx_approve_req,
                                           &tx_approve_res) == RC_OK) {
    flex_hash_to_char_buffer(tx_approve_res->trunk, hash_txt);
    printf("trunk: %s\n", hash_txt->data);
    flex_hash_to_char_buffer(tx_approve_res->branch, hash_txt);
    printf("branch: %s\n", hash_txt->data);
  }

  get_transactions_to_approve_req_free(&tx_approve_req);
  get_transactions_to_approve_res_free(&tx_approve_res);
  char_buffer_free(hash_txt);
}

void test_broadcast_tx(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  broadcast_transactions_req_t *req = broadcast_transactions_req_new();
  req = broadcast_transactions_req_add(req, TRYRES_2673);
  if (iota_client_broadcast_transactions(s, req)) {
    printf("broadcast_tx failed.\n");
  } else {
    printf("broadcast_tx done.\n");
  }
  broadcast_transactions_req_free(req);
}

void test_store_tx(iota_client_service_t *s) {
  printf("\n[%s]\n", __FUNCTION__);
  store_transactions_req_t *req = store_transactions_req_new();
  req = store_transactions_req_add(req, TRYRES_2673);
  if (iota_client_store_transactions(s, req)) {
    printf("store_tx failed.\n");
  } else {
    printf("store_tx done.\n");
  }
  store_transactions_req_free(req);
}

#define HOST "localhost"
#define PORT 14265

int main() {
  iota_client_service_t serv;
  serv.http.host = HOST;
  serv.http.port = PORT;
  serv.http.api_version = 1;
  serv.serializer_type = SR_JSON;
  logger_init();
  logger_output_register(stdout);
  logger_output_level_set(stdout, LOGGER_DEBUG);
  iota_client_core_init(&serv);

  test_find_trans(&serv); sleep(1);
  test_node_info(&serv); sleep(1);
  test_get_neighbors(&serv); sleep(1);
  test_add_neighbors(&serv); sleep(1);
  test_remove_neighbors(&serv); sleep(1);
  test_get_tips(&serv); sleep(1);
  test_get_trytes(&serv); sleep(1);
  test_attach_to_tangle(&serv); sleep(1);
  test_check_consistency(&serv); sleep(1);

  test_get_inclustion(&serv); sleep(1);
  test_get_balance(&serv); sleep(1);
  test_tx_to_approve(&serv); sleep(1);
  test_broadcast_tx(&serv); sleep(1);
  test_store_tx(&serv);
  iota_client_core_destroy(&serv);
  return 0;
}

