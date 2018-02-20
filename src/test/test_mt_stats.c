#define CIRCUITLIST_PRIVATE
#define MT_STATS_PRIVATE

#include <stdio.h>
#include <stdlib.h>

#include "or.h"
#include "circuitlist.h"
#include "crypto.h"
#include "config.h"
#include "test.h"
#include "mt_stats.h"

#pragma GCC diagnostic ignored "-Wbad-function-cast"

#define EPSILON 0.1

#define TIME_STEPS 50000
#define CIRC_PROB 0.1
#define SEND_PROB 0.5

typedef struct {
  int test_counts;
} test_data_t;

typedef struct {
  int publish_counts;
  int time_profiles;
  double total_counts;
} validation_data_t;

// helper functions
static time_t mock_time(void);
static void mock_publish_to_disk(const char* filename, smartlist_t* time_profiles_buckets,
			       smartlist_t* total_counts_buckets, smartlist_t* time_stdevs_buckets);
static circuit_t* new_circ(void);
static uint16_t rand_port(void);
static int compare_random(const void **a, const void **b);
static void test_mt_stats(void *arg);

static smartlist_t* active_circs;
static time_t current_time;

static smartlist_t* test_data[MT_NUM_PORT_GROUPS];
static int recorded_counts[MT_NUM_PORT_GROUPS];
static int written_counts[MT_NUM_PORT_GROUPS];

static validation_data_t validation_data;

static void test_mt_stats(void *arg)
{
  (void)arg;

  MOCK(mt_time, mock_time);
  MOCK(mt_publish_to_disk, mock_publish_to_disk);

  /************************* Setup *************************/

  or_options_t* options = (or_options_t*)get_options();
  options->MoneTorStatistics = 1.0;
  current_time = 1000;
  srand(42);
  mt_stats_init();

  active_circs = smartlist_new();

  for(int i = 0; i < MT_NUM_PORT_GROUPS; i++)
    test_data[i] = smartlist_new();

  /************************* Test **************************/

  for(int i = 0; i < TIME_STEPS; i++){

    // randomly add a new circuit
    if((double)(rand())/RAND_MAX < CIRC_PROB){
      circuit_t* circ_create = new_circ();
      mt_stats_circ_create(circ_create);
      mt_stats_circ_port(circ_create);
      smartlist_add(active_circs, circ_create);
    }

    // shuffle circuits
    smartlist_sort(active_circs, compare_random);
    circuit_t* circ_destroy;

    // loop through active circuits and randomly increment
    SMARTLIST_FOREACH_BEGIN(active_circs, circuit_t*, circ) {
      if((double) rand()/RAND_MAX < SEND_PROB){
	mt_stats_circ_increment(circ);
      }
    } SMARTLIST_FOREACH_END(circ);

    // randomly destroy a circuit
    if(((double)rand()/RAND_MAX < CIRC_PROB) &&
       (circ_destroy = smartlist_pop_last(active_circs))){

      mt_stats_t* stats = &TO_OR_CIRCUIT(circ_destroy)->mt_stats;

      // record test stats for later validation
      if(stats->port && stats->total_count > 0){
	test_data_t* data = tor_malloc(sizeof(test_data_t));
	data->test_counts = stats->total_count;
	uint group = mt_port_group(stats->port);
	smartlist_add(test_data[group], data);
	recorded_counts[group]++;
      }

      mt_stats_circ_record(circ_destroy);
      circuit_free(circ_destroy);
    }

    for(int j = 0; j < MT_NUM_PORT_GROUPS; j++){
      if(recorded_counts[j] % (MT_BUCKET_SIZE * MT_BUCKET_NUM) == 0){
	written_counts[j] = recorded_counts[j];
      }
    }

    mt_stats_publish();
    current_time++;
  }

  /************************ Validate ***********************/

  int publish_counts_total = 0;
  int test_counts_total = 0;

  for(int i = 0; i < MT_NUM_PORT_GROUPS; i++){
    publish_counts_total += written_counts[i] / (MT_BUCKET_SIZE * MT_BUCKET_NUM);

    for(int j = 0; j < written_counts[i]; j++){
      test_counts_total += ((test_data_t*)smartlist_get(test_data[i], j))->test_counts;
    }
  }

  int total_counts_diff = test_counts_total - validation_data.time_profiles;
  total_counts_diff = total_counts_diff > 0? total_counts_diff : -total_counts_diff;

  tt_assert(test_counts_total == validation_data.time_profiles);
  tt_assert(total_counts_diff < EPSILON);

 done:

  UNMOCK(mt_time);
  UNMOCK(mt_publish_to_disk);

  SMARTLIST_FOREACH_BEGIN(active_circs, circuit_t*, circ){
    circuit_free(circ);
  } SMARTLIST_FOREACH_END(circ);
  smartlist_free(active_circs);

  for(int i = 0; i < MT_NUM_PORT_GROUPS; i++){
    SMARTLIST_FOREACH_BEGIN(test_data[i], test_data_t*, cp){
      tor_free(cp);
    } SMARTLIST_FOREACH_END(cp);
    smartlist_free(test_data[i]);
  }
}

struct testcase_t mt_stats_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_stats", test_mt_stats, 0, NULL, NULL },
  END_OF_TESTCASES
};

static time_t mock_time(void){
  return current_time;
}

static void mock_publish_to_disk(const char* filename, smartlist_t* time_profiles_buckets,
			       smartlist_t* total_counts_buckets, smartlist_t* time_stdevs_buckets){
  (void)filename;

  validation_data.publish_counts++;

  tor_assert(smartlist_len(total_counts_buckets) == MT_BUCKET_NUM);
  tor_assert(smartlist_len(time_stdevs_buckets) == MT_BUCKET_NUM);

  for(int i = 0; i < smartlist_len(time_profiles_buckets); i++){
    validation_data.time_profiles += *(int*)smartlist_get(time_profiles_buckets, i);
  }

  for(int i = 0; i < smartlist_len(total_counts_buckets); i++){
    validation_data.total_counts += *(double*)smartlist_get(total_counts_buckets, i) * MT_BUCKET_SIZE;
  }
}

static circuit_t* new_circ(void){
  or_circuit_t* or_circ = or_circuit_new(0, NULL);

  int add_stream = 1;
  uint16_t port = rand_port();

  // add at least 1 plus a random number of stream of the same port
  while(add_stream){
    edge_connection_t* edge_conn = tor_calloc(1, sizeof(edge_connection_t));
    TO_CONN(edge_conn)->port = port;
    or_circ->n_streams = edge_conn;
    add_stream = rand() % 2;
  }

  return TO_CIRCUIT(or_circ);
}

static uint16_t rand_port(void){

  int group = rand() % MT_NUM_PORT_GROUPS;
  int result = 0;

  switch(group){
    case MT_PORT_GROUP_WEB:
      return rand() % 2 == 0 ? 80 : 443;
    case MT_PORT_GROUP_LOW:
      while(!(result != 0 && result != 80 && result != 443 && result < 1000))
	result = rand();
      return result;
    case MT_PORT_GROUP_OTHER:
      while(!(result >= 1000))
	result = rand();
      return result;
  }

  return result;
}

static int compare_random(const void **a, const void **b){
  (void)a;
  (void)b;
  if(rand() % 2 == 0)
    return 1;
  return -1;
}
