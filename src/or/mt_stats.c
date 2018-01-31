#include "or.h"
#include "crypto.h"
#include "container.h"
#include "config.h"
#include "mt_stats.h"

#define MAX_INT_STRING "2147483647"

static const char* mt_directory = "live_data";
static int counter = 0;

void mt_stats_init(circuit_t* circ){

  or_circuit_t* or_circ = TO_OR_CIRCUIT(circ);

  if(crypto_rand_int(100) < MT_COLLECT_PROB){
    or_circ->mt_stats.is_collectable = 1;
    or_circ->mt_stats.start_time = time(NULL);
    or_circ->mt_stats.time_buckets = smartlist_new();

    /** make sure there is only one port in use and record it */
    tor_assert(or_circ->n_streams && !or_circ->n_streams->next_stream);
    connection_t* stream = TO_CONN(or_circ->n_streams);
    or_circ->mt_stats.port = stream->port;
  }
}

void mt_stats_increment(circuit_t* circ){

  if(get_options()->MoneTorStatistics && !CIRCUIT_IS_ORIGIN(circ) &&
     TO_OR_CIRCUIT(circ)->mt_stats.is_collectable){

    mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;

    // increment total cell count
    stats->total_cells++;

    // add new time buckets if enough time has passed
    time_t time_diff = time(NULL) - stats->start_time;
    int num_buckets = smartlist_len(stats->time_buckets);
    int exp_buckets = (time_diff + MT_TIME_BUCKET - 1) / MT_TIME_BUCKET;
    for(int i = 0; i < exp_buckets - num_buckets; i++)
      smartlist_add(stats->time_buckets, tor_calloc(1, sizeof(int)));

    // increment the cell count in the latest time bucket
    int* cur_bucket = smartlist_get(stats->time_buckets, exp_buckets -1);
    (*cur_bucket)++;
  }
}

void mt_stats_record(circuit_t* circ){

  if(get_options()->MoneTorStatistics && !CIRCUIT_IS_ORIGIN(circ) &&
     TO_OR_CIRCUIT(circ)->mt_stats.is_collectable){

    mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;
    smartlist_t* bucket_strings = smartlist_new();
    for(int i = 0; i < smartlist_len(stats->time_buckets); i++){
      int* count = smartlist_get(stats->time_buckets, i);
      smartlist_add_asprintf(bucket_strings, "%d", *count);

      struct stat st = {0};
      if (stat(mt_directory, &st) == -1) {
	mkdir(mt_directory, 0700);
      }

      char* bucket_string = smartlist_join_strings(bucket_strings, ", ", 0, NULL);
      char port_string[strlen(MAX_INT_STRING)];
      sprintf(port_string, "%u", stats->port);

      char filename[strlen(mt_directory) + 1 + strlen(MAX_INT_STRING)];
      sprintf(filename, "%s/%d", mt_directory, counter);

      FILE* fp = fopen(filename, "a");
      fprintf(fp, "%s, %s", port_string, bucket_string);
      fclose(fp);
    }
  }
}
