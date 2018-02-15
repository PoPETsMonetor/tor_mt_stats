#include "math.h"
#include "or.h"
#include "crypto.h"
#include "container.h"
#include "config.h"
#include "mt_stats.h"

#pragma GCC diagnostic ignored "-Wstack-protector"

#define MAX_UINT_STRING "4294967295"

typedef struct {
  smartlist_t* total_counts;
  smartlist_t* time_profiles;
  smartlist_t* time_deviations;
} stats_t;

typedef struct {
  double sum;
  uint32_t count;
} entry_t;

static digestmap_t* global_stats;  // map port group -> stats_t

static int count;
static time_t prev;
static const char* mt_directory = "moneTor_live_data";

void mt_stats_init(void){
  global_stats = digestmap_new();
  // initialize global_stats element for each port group
}

void mt_stats_circ_create(circuit_t* circ){

  if(!CIRCUIT_IS_ORIGIN(circ) && crypto_rand_double() < get_options()->MoneTorStatistics){

    mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;

    log_info(LD_GENERAL, "mt_stats %u", TO_OR_CIRCUIT(circ)->p_circ_id);
    stats->collecting = 1;
    stats->port = 0;
    stats->start_time = mt_time();
    stats->time_profiles = smartlist_new();
  }
}

void mt_stats_circ_port(circuit_t* circ){

 if(!CIRCUIT_IS_ORIGIN(circ) && TO_OR_CIRCUIT(circ)->mt_stats.collecting){

   mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;
   or_circuit_t* or_circ = TO_OR_CIRCUIT(circ);

   if(or_circ->n_streams){
     /** make sure there is only one port in use and record it */
     //tor_assert(or_circ->n_streams && !or_circ->n_streams->next_stream);
     connection_t* stream = TO_CONN(or_circ->n_streams);
     if(stats->port && stats->port != stream->port)
       stats->is_multiport = 1;
     stats->port = stream->port;
     log_info(LD_GENERAL, "mt_stats %u %u", or_circ->p_circ_id, stream->port);
   }
 }
}

void mt_stats_circ_increment(circuit_t* circ){

  if(!CIRCUIT_IS_ORIGIN(circ) && TO_OR_CIRCUIT(circ)->mt_stats.collecting){

    mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;

    // increment total cell count
    stats->total_cells++;

    // add new time buckets if enough time has passed
    time_t time_diff = mt_time() - stats->start_time;
    int num_buckets = smartlist_len(stats->time_profiles);
    int exp_buckets = time_diff / MT_BUCKET_TIME + 1;
    for(int i = 0; i < exp_buckets - num_buckets; i++)
      smartlist_add(stats->time_profiles, tor_calloc(1, sizeof(int)));

    // increment the cell count in the latest time bucket
    int* cur_bucket = smartlist_get(stats->time_profiles, exp_buckets -1);
    (*cur_bucket)++;
  }
}

void mt_stats_circ_record(circuit_t* circ){

  if(!CIRCUIT_IS_ORIGIN(circ) && TO_OR_CIRCUIT(circ)->mt_stats.collecting){

    mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;
    smartlist_t* bucket_strings = smartlist_new();

    // only record if there was exit data associated with the circuit
    if(stats->port){
      log_info(LD_GENERAL, "mt_stats %u", TO_OR_CIRCUIT(circ)->p_circ_id);

      for(int i = 0; i < smartlist_len(stats->time_profiles); i++){
	int* count = smartlist_get(stats->time_profiles, i);
	smartlist_add_asprintf(bucket_strings, "%d", *count);
      }

      struct stat st = {0};
      if (stat(mt_directory, &st) == -1) {
	mkdir(mt_directory, 0700);
      }

      // TODO: add to total_circ --> need to decide on bucket sizes

      // increment global time profiles
      for(int i = 0; i < smartlist_len(stats->time_profiles); i++){

	entry_t* stat;

	// retrieve the appropriate item from the list or add one if non exists
	if(i < smartlist_len(time_profiles)){
	  stat = smartlist_get(time_profiles, i);
	}
	else {
	  stat = tor_calloc(1, sizeof(entry_t));
	  smartlist_add(time_profiles, stat);
	}

	stat->sum += *smartlist_get(stats->time_profiles, i);
	stat->count++;
      }
    }

    // calculate standard deviation of circuit time profile
    int sum = 0;
    int mean = 0;
    int diff_squares = 0;
    double stdev = 0;

    for(int i = 0; i < smartlist_len(stats->time_profiles); i++){
      int += smartlist_get(stats->time_profiles, i);
    }

    mean = sum / smartlist_len(stats->time_profiles);

    for(int i = 0; i < smartlist_len(stats->time_profiles); i++){
      int diff = smartlist_get(stats->time_profiles, i) - mean;
      diff_squares += diff * diff;
    }

    stdev = sqrt(diff_squares / smartlist_len(stats->time_profiles));

    // TODO: place stdevs into buckets

    // free circ time_profile items
    SMARTLIST_FOREACH_BEGIN(stats, entry_t*, cp) {
      tor_free(cp);
    } SMARTLIST_FOREACH_END(cp);

    // free circ time_profile
    smartlist_free(stats->time_profiles);
  }
}

void mt_stats_dump(void){

  time_t now = mt_time();

  // do this every hour
  if(localtime(&now)->tm_yday > localtime(&prev)->tm_yday){

    // define filename based on time
    char filename[strlen(mt_directory) + strlen(MAX_UINT_STR) + 1] = {0};
    memcpy(filename, mt_directory, strlen(mt_directory));
    sprintf(filename + strlen(mt_directory), "_%03d", count++);

    // write port as ascii
    char port_string[strlen(MAX_UINT_STR) + 1] = {0};
    sprintf(port_string, "%u",
    char* total_counts_string = smartlist_join_strings(total_counts, ", ", 0, NULL);
    char* time_profiles_string = smartlist_join_strings(time_profiles, ", ", 0, NULL);
    char* time_deviations_string = smartlist_join_strings(time_deviations, ", ", 0, NULL);

    FILE* fp = fopen(filename, "a");
    fprintf(fp, "%s\n", port_string);
    fprintf(fp, "%s\n", total_counts_string);
    fprintf(fp, "%s\n", time_profiles_string);
    fprintf(fp, "%s\n", time_deviations_string);
    fclose(fp);

    // free strings
    tor_free(total_counts_strings);
    tor_free(time_profiles_strings);
    tor_free(time_deviations_strings);

    // free smartlist elements
    SMARTLIST_FOREACH_BEGIN(total_cell_counts, entry_t*, cp) {
      tor_free(cp);
    } SMARTLIST_FOREACH_END(cp);
    SMARTLIST_FOREACH_BEGIN(time_profiles, entry_t*, cp) {
      tor_free(cp);
    } SMARTLIST_FOREACH_END(cp);
    SMARTLIST_FOREACH_BEGIN(time_deviations, entry_t*, cp) {
      tor_free(cp);
    } SMARTLIST_FOREACH_END(cp);

    // free smartlists
    smartlist_free(total_counts);
    smartlist_free(time_profiles);
    smartlist_free(time_deviations);

    // reinitialize smartlists
    total_count = smartlist_new();
    time_profiles = smartlist_new();
    time_deviaitons = smartlist_new();

    prev = now;
  }
}

MOCK_IMPL(time_t, mt_time, (void)){
  return approx_time();
}
