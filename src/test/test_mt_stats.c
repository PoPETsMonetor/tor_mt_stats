#include "or.h"
#include "circuitlist.h"
#include "crypto.h"
#include "config.h"
#include "test.h"
#include "mt_stats.h"

#define NUM_CIRCS 20
#define TIME_STEPS 4000

static time_t current_time;
time_t mock_time(void);

time_t mock_time(void){
  return current_time;
}

static void circ_init(circuit_t** circ){
  or_circuit_t* or_circ = or_circuit_new(0, NULL);
  edge_connection_t* edge_conn = tor_calloc(1, sizeof(edge_connection_t));
  TO_CONN(edge_conn)->port = 80;
  or_circ->n_streams = edge_conn;
  *circ = TO_CIRCUIT(or_circ);
}

static void test_mt_stats(void *arg)
{
  (void)arg;

  MOCK(mt_time, mock_time);

  /****************** Setup Fake Tor Stuff *****************/

  or_options_t* options = (or_options_t*)get_options();
  options->MoneTorStatistics = 1;
  current_time = 1000;

  circuit_t* circs[NUM_CIRCS];

  for(int i = 0; i < NUM_CIRCS; i++){
    circ_init(&circs[i]);
  }

  /************************* Test **************************/

  // initialize first half of circs
  for(int i = 0; i < NUM_CIRCS / 2; i++){
    // keep trying to init until we get lucky
    while(!TO_OR_CIRCUIT(circs[i])->mt_stats.is_collectable){
      mt_stats_init(circs[i]);
    }
  }

  // do one round of incrementing
  for(int i = 0; i < TIME_STEPS / 2; i++){
    for(int j = 0; j < NUM_CIRCS / 2; j++){
      if(crypto_rand_int(3) == 0){
	mt_stats_increment(circs[j]);
      }
    }
    current_time++;

    if(crypto_rand_int(100) == 0){
      current_time += crypto_rand_int(120);
    }
  }

  // initialize second half of circs
  for(int i = NUM_CIRCS / 2; i < NUM_CIRCS; i++){
    // keep trying to init until we get lucky
    while(!TO_OR_CIRCUIT(circs[i])->mt_stats.is_collectable){
      mt_stats_init(circs[i]);
    }
  }

  // record first quarter of circuits
  for(int i = 0; i < NUM_CIRCS / 4; i++){
    mt_stats_record(circs[i]);
  }

  // do second round of incrementing
  for(int i = TIME_STEPS / 2; i < TIME_STEPS; i++){
    for(int j = NUM_CIRCS / 4; j < NUM_CIRCS; j++){
      if(crypto_rand_int(3) == 0){
	mt_stats_increment(circs[j]);
      }
    }
    current_time++;

    if(crypto_rand_int(100) == 0){
      current_time += crypto_rand_int(120);
    }
  }

  // record last three quarters of circuits
  for(int i = NUM_CIRCS / 4; i < NUM_CIRCS; i++){
    mt_stats_record(circs[i]);
  }


 done:;

  for(int i = 0; i < NUM_CIRCS; i++){
    tor_free(TO_OR_CIRCUIT(circs[i])->n_streams);
    circuit_free(circs[i]);
  }

  UNMOCK(mt_time);
}

struct testcase_t mt_stats_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_stats", test_mt_stats, 0, NULL, NULL },
  END_OF_TESTCASES
};
