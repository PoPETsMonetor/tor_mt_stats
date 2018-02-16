/**
 * \file mt_stats.c
 *
 * \brief Implement logic for recording statistics relevant for
 *    the moneTor payment project.
 *
 * This module hooks onto various parts of the the Tor codebase in order to
 * record relevant statistics that will be used for analysis in designing the
 * core moneTor protocols. The statistics collected are on a per-port-group
 * basis and written to the disk whenver a sufficient number of circuits have
 * been recorded for anonymity purposes. The following three types of statistics
 * are collected:
 *
 * <ul>
 *   <li> Time Profiles - Number of cells processed in each time interval from
 *        the circuit start time; aggregated over circuits by simple addition
 *   <li> Total Counts - Total number of cells processed by a circuit; aggregated
 *        by sorting and taking the mean of fixed-size nearest neighbor buckets
 *   <li> Time Stdevs - Standard deviation across the time profiles of individual
 *        circuits; aggregated by sorting and taking the mean of fixed-size
 *        nearest neighbor buckets
 * </ul>
 *
 * Tor codebase hooks are located in the following modules:
 *
 * <ul>
 *   <li> <b>mt_stats_init()</b> <--- <b>main.c</b>
 *   <li> <b>mt_stats_circ_create()</b> <--- <b>command.c</b>
 *   <li> <b>mt_stats_circ_port()</b> <--- <b>connection_edge.c</b>
 *   <li> <b>mt_stats_circ_increment()</b> <--- <b>relay.c</b>
 *   <li> <b>mt_stats_circ_record()</b> <--- <b>circuitlist.c</b>
 *   <li> <b>mt_stats_circ_dump()</b> <--- <b>main.c</b>
 * </ul>
 */

#include <stdlib.h>
#include <math.h>

#include "or.h"
#include "crypto.h"
#include "container.h"
#include "config.h"
#include "mt_stats.h"

#pragma GCC diagnostic ignored "-Wstack-protector"

#define BUCKET_SIZE 50
#define BUCKET_NUM 50

/**
 * Track one set of data for each of these port groups
 */
#define NUM_PORT_GROUPS 3
#define PORT_GROUP_OTHER 0
#define PORT_GROUP_WEB 1
#define PORT_GROUP_LOW 2

#define MAX_UINT_STRING "4294967295"

/**
 * Data tracked for each port groups. Each smartlist records pointers to an
 * entry_t struct
 */
typedef struct {
  int num_circuits;
  smartlist_t* time_profiles;
  int total_counts[BUCKET_SIZE * BUCKET_NUM];
  double time_stdevs[BUCKET_SIZE * BUCKET_NUM];
} data_t;

// helper functions
static int get_port_group(uint16_t port);
static const char* get_port_group_string(int port_group);
static smartlist_t* bucketize_total_counts(int (*total_counts)[BUCKET_SIZE * BUCKET_NUM]);
static smartlist_t* bucketize_time_stdevs(double (*time_stdevs)[BUCKET_SIZE * BUCKET_NUM]);
static int int_comp(const void* a, const void* b);
static int double_comp(const void* a, const void* b);

// global data that will eventually be dumped to disk
static data_t data[NUM_PORT_GROUPS];

// index of the next session of data to be dumped to disk
static int session_num[NUM_PORT_GROUPS];
static const char* mt_directory = "moneTor_live_data";

/**
 * Globally initialize the mt_stats module. Should only be called once outside
 * of the module.
 */
void mt_stats_init(void){
  for(int i = 0; i < NUM_PORT_GROUPS; i++){
    data[i].time_profiles = smartlist_new();
  }
}

/**
 * Create the mt_stat structures necessary to record an individual circuit
 */
void mt_stats_circ_create(circuit_t* circ){

  // exit if circuit does not pass the random filter
  if(CIRCUIT_IS_ORIGIN(circ) || !(crypto_rand_double() < get_options()->MoneTorStatistics))
    return;

  mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;

  stats->collecting = 1;
  stats->port = 0;
  stats->start_time = mt_time();
  stats->time_profile = smartlist_new();

}

/**
 * Record the port for an exit circuit. The expectation is that isolation flags
 * are set directly. If a port is found that conflicts with a previous port from
 * this circuit then an assertion error will be thrown
 */
void mt_stats_circ_port(circuit_t* circ){

  // exit if the circuit is not marked for stat collection
  if(CIRCUIT_IS_ORIGIN(circ) || !TO_OR_CIRCUIT(circ)->mt_stats.collecting)
    return;

  mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;
  or_circuit_t* or_circ = TO_OR_CIRCUIT(circ);

  if(or_circ->n_streams){
    connection_t* stream = TO_CONN(or_circ->n_streams);
    tor_assert(!stats->port || stats->port == stream->port);
    stats->port = stream->port;
  }
}

/**
 * Alert an mt_stats circuit that a single cell has been processed
 */
void mt_stats_circ_increment(circuit_t* circ){

  // exit if the circuit is not marked for stat collection
  if(CIRCUIT_IS_ORIGIN(circ) || !TO_OR_CIRCUIT(circ)->mt_stats.collecting)
    return;

  mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;

  // increment total cell count
  stats->total_count++;

  // add new time buckets if enough time has passed
  time_t time_diff = mt_time() - stats->start_time;
  int num_buckets = smartlist_len(stats->time_profile);
  int exp_buckets = time_diff / MT_BUCKET_TIME + 1;
  for(int i = 0; i < exp_buckets - num_buckets; i++)
    smartlist_add(stats->time_profile, tor_calloc(1, sizeof(int)));

  // increment the cell count in the latest time bucket
  int* cur_bucket = smartlist_get(stats->time_profile, exp_buckets -1);
  (*cur_bucket)++;
}

/**
 * At the end of a circuit's lifetime, record the mt_stats data to the global
 * record
 */
void mt_stats_circ_record(circuit_t* circ){

  // exit if the circuit is not marked for stat collection
  if(CIRCUIT_IS_ORIGIN(circ) || !TO_OR_CIRCUIT(circ)->mt_stats.collecting)
    return;

  mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;

  // if the port was never set then the exit stream was never used
  if(!stats->port){
    stats->collecting = 0;
    smartlist_free(stats->time_profile);
    return;
  }


  // obtain global data for the right port group
  int group = get_port_group(stats->port);

  // if circuits exceeded this then something went wrong with dumping
  tor_assert(data[group].num_circuits < BUCKET_SIZE * BUCKET_NUM);

  /*********************** Record Time Profiles ********************/

  int num_buckets = smartlist_len(stats->time_profile);

  // increase global time profiles length if necessary
  for(int i = smartlist_len(data[group].time_profiles); i < num_buckets; i++)
    smartlist_add(data[group].time_profiles, tor_calloc(1, sizeof(int)));

  for(int i = 0; i < num_buckets; i++){
    int* bucket = smartlist_get(data[group].time_profiles, i);
    *bucket += *(int*)smartlist_get(stats->time_profile, i);
  }

  /******************** Record Total Cell Counts *******************/

  data[group].total_counts[data[group].num_circuits] = stats->total_count;

  /************** Record Time Profile Standard Deviations **********/

  // calculate standard deviation of circuit time profile
  int sum = 0;
  int mean = 0;
  int diff_squares = 0;
  double stdev = 0;

  for(int i = 0; i < smartlist_len(stats->time_profile); i++){
    sum += *(int*)smartlist_get(stats->time_profile, i);
  }

  mean = sum / smartlist_len(stats->time_profile);

  for(int i = 0; i < smartlist_len(stats->time_profile); i++){
    int diff = *(int*)smartlist_get(stats->time_profile, i) - mean;
    diff_squares += diff * diff;
  }

  stdev = sqrt(diff_squares / smartlist_len(stats->time_profile));

  data[group].time_stdevs[data[group].num_circuits] = stdev;

  /*****************************************************************/

  data[group].num_circuits++;

  // free circ time_profile items and smartlist
  SMARTLIST_FOREACH_BEGIN(stats->time_profile, int*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(stats->time_profile);
}

/**
 * Dump the global statistics collection data, clear the memory, and prepare for
 * the next session
 */
void mt_stats_dump(void){

  int group = -1;

  // loop through port groups and see if one of them is ready for dumping
  for(int i = 0; i < NUM_PORT_GROUPS; i++){

    // only one port group should be ready to be dumped at a time
    tor_assert(group == -1 || data[i].num_circuits < BUCKET_SIZE * BUCKET_NUM);

    if(data[i].num_circuits == BUCKET_SIZE * BUCKET_NUM)
      group = i;
  }

  // if no port groups are ready to be dumped then exit
  if(group == -1)
    return;

  // create filename based on port group and session number
  const char* group_string = get_port_group_string(group);
  int filename_size = strlen(group_string) + 1 + strlen(MAX_UINT_STRING);
  char filename[filename_size];
  memset(filename, '\0', filename_size);
  sprintf(filename, "%s_%d", group_string, session_num[group]++);

  smartlist_t* total_counts_buckets = bucketize_total_counts(&data[group].total_counts);
  smartlist_t* time_stdevs_buckets = bucketize_time_stdevs(&data[group].time_stdevs);

  char* time_profiles_string = smartlist_join_strings(data[group].time_profiles, ", ", 0, NULL);
  char* total_counts_string = smartlist_join_strings(total_counts_buckets, ", ", 0, NULL);
  char* time_stdevs_string = smartlist_join_strings(time_stdevs_buckets, ", ", 0, NULL);

  FILE* fp = fopen(filename, "w");
  fprintf(fp, "%s\n", time_profiles_string);
  fprintf(fp, "%s\n", total_counts_string);
  fprintf(fp, "%s\n", time_stdevs_string);
  fclose(fp);

  // free strings
  tor_free(time_profiles_string);
  tor_free(total_counts_string);
  tor_free(time_stdevs_string);

  // free smartlists
  SMARTLIST_FOREACH_BEGIN(data[group].time_profiles, int*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(data[group].time_profiles);

  SMARTLIST_FOREACH_BEGIN(total_counts_buckets, double*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(total_counts_buckets);

  SMARTLIST_FOREACH_BEGIN(time_stdevs_buckets, double*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(time_stdevs_buckets);

  // reinitialize global data fields
  data[group].time_profiles = smartlist_new();
}

/**
 * MOCKABLE time for testing purposes
 */
MOCK_IMPL(time_t, mt_time, (void)){
  return approx_time();
}

/**
 * Returns the general port group to which a given port belongs
 */
static int get_port_group(uint16_t port){

  if(port == 80 || port == 443)
    return PORT_GROUP_WEB;
  if(port < 1000)
    return PORT_GROUP_LOW;

  return PORT_GROUP_OTHER;
}

/**
 * Returns a string literal representing a numerical port group
 */
static const char* get_port_group_string(int port_group){

  switch(port_group){
    case PORT_GROUP_OTHER:
      return "port_group_other";
    case PORT_GROUP_WEB:
      return "port_group_web";
    case PORT_GROUP_LOW:
      return "port_group_low";
    default:
      return NULL;
  }
}

/**
 * Accepts an array of integers and returns a smartlist of
 * doubles. Conceptionally, original data is sorted and broken up into
 * BUCKET_NUM number sets of BUCKET_SIZE number of elements. The returned
 * valuesare the mean of each bucket
 */
static smartlist_t* bucketize_total_counts(int (*total_counts)[BUCKET_SIZE * BUCKET_NUM]){

  qsort(*total_counts, BUCKET_SIZE * BUCKET_NUM, sizeof(int), int_comp);
  smartlist_t* result = smartlist_new();

  for(int i = 0; i < BUCKET_NUM; i++){
    double sum = 0;
    for(int j = 0; j < BUCKET_SIZE; i++)
      sum += (*total_counts)[i * BUCKET_SIZE + j];

    double* mean = tor_malloc(sizeof(double));
    *mean = sum / BUCKET_SIZE;
    smartlist_add(result, mean);
  }

  return result;
}

/**
 * Accepts an array of doubles and returns a smartlist of
 * doubles. Conceptionally, original data is sorted and broken up into
 * BUCKET_NUM number sets of BUCKET_SIZE number of elements. The returned
 * valuesare the mean of each bucket
 */
static smartlist_t* bucketize_time_stdevs(double (*time_stdevs)[BUCKET_SIZE * BUCKET_NUM]){

  qsort(*time_stdevs, BUCKET_SIZE * BUCKET_NUM, sizeof(double), double_comp);
  smartlist_t* result = smartlist_new();

  for(int i = 0; i < BUCKET_NUM; i++){
    double sum = 0;
    for(int j = 0; j < BUCKET_SIZE; i++)
      sum += (*time_stdevs)[i * BUCKET_SIZE + j];

    double* mean = tor_malloc(sizeof(double));
    *mean = sum / BUCKET_SIZE;
    smartlist_add(result, mean);
  }

  return result;
}

/**
 * Integer comparator function for qsort
 */
static int int_comp(const void* a, const void* b){
  return (int*)a - (int*)b;
}

/**
 * Double comparator function for qsort
 */
static int double_comp(const void* a, const void* b){
    return (double*)a - (double*)b;
}
