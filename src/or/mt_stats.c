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
 *   <li> <b>mt_stats_circ_publish()</b> <--- <b>main.c</b>
 * </ul>
 */

#define MT_STATS_PRIVATE
#include <stdlib.h>
#include <math.h>

#include "or.h"
#include "crypto.h"
#include "container.h"
#include "config.h"
#include "mt_stats.h"

#pragma GCC diagnostic ignored "-Wstack-protector"

#define MAX_UINT_STRING "4294967295"

/**
 * Data tracked for each port groups. Each smartlist records pointers to an
 * entry_t struct
 */
typedef struct {
  int num_circuits;
  smartlist_t* time_profiles;
  int total_counts[MT_BUCKET_SIZE * MT_BUCKET_NUM];
  double time_stdevs[MT_BUCKET_SIZE * MT_BUCKET_NUM];
} data_t;

// helper functions
static const char* get_port_group_string(int port_group);
static smartlist_t* bucketize_total_counts(int (*total_counts)[MT_BUCKET_SIZE * MT_BUCKET_NUM]);
static smartlist_t* bucketize_time_stdevs(double (*time_stdevs)[MT_BUCKET_SIZE * MT_BUCKET_NUM]);
static int int_comp(const void* a, const void* b);
static int double_comp(const void* a, const void* b);

// global data that will eventually be dumped to disk
static data_t data[MT_NUM_PORT_GROUPS];

// index of the next session of data to be dumped to disk
static int session_num[MT_NUM_PORT_GROUPS];
static const char* directory = "mt_stats/published";

/**
 * Globally initialize the mt_stats module. Should only be called once outside
 * of the module.
 */
void mt_stats_init(void){
  for(int i = 0; i < MT_NUM_PORT_GROUPS; i++){
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
  stats->time_profile = smartlist_new();
}

/**
 * Record the port group for an exit circuit.
 *
 * If we observe multiple group, we set this circuit to MT_PORT_GROUP_MULTIPLE
 *
 * Called each time we succeed dns_resolve()
 */
void mt_stats_circ_port(circuit_t* circ, edge_connection_t* n_stream){

  // exit if the circuit is not marked for stat collection
  if(CIRCUIT_IS_ORIGIN(circ) || !TO_OR_CIRCUIT(circ)->mt_stats.collecting)
    return;

  mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;
  /** This should match the timing of the first CONNECTED
   * cell that this circuit sent back */
  if (!stats->port_group)
    stats->start_time = mt_time();
  /** We consider group instead of port, directly */
  connection_t* curr_stream = TO_CONN(n_stream);
  if (!stats->port_group) {
    stats->port_group = mt_port_group(curr_stream->port);
    log_info(LD_GENERAL, "MT_STATS: giving port group %s", get_port_group_string(stats->port_group));
  }
  else {
    if (stats->port_group != mt_port_group(curr_stream->port)) {
      stats->handle_multiple_group_port = 1;
      /** If we notice this circuit handle more than one group
       * port, we simply change its type to MT_PORT_GROUP_MULTIPLE */
      stats->port_group = MT_PORT_GROUP_MULTIPLE;
      log_info(LD_GENERAL, "MT_STATS: moving port group to %s", get_port_group_string(stats->port_group));
    }
  }
}

/**
 * Alert an mt_stats circuit that a single cell has been processed
 */
void mt_stats_circ_increment(circuit_t* circ){

  // exit if the circuit is not marked for stat collection
  if(CIRCUIT_IS_ORIGIN(circ) || !TO_OR_CIRCUIT(circ)->mt_stats.collecting ||
      !TO_OR_CIRCUIT(circ)->mt_stats.port_group)
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

  // if the port was never set or used then the exit stream was never used
  if(!stats->port_group || !stats->total_count){
    stats->collecting = 0;
    smartlist_free(stats->time_profile);
    return;
  }

  log_info(LD_GENERAL, "MT_STATS: recording information for port group %s",
      get_port_group_string(stats->port_group));

  // obtain global data for the right port group
  int group = stats->port_group;

  // if circuits exceeded this then something went wrong with dumping
  tor_assert_nonfatal(data[group-1].num_circuits < MT_BUCKET_SIZE * MT_BUCKET_NUM);

  /*********************** Record Time Profiles ********************/

  int num_buckets = smartlist_len(stats->time_profile);

  // increase global time profiles length if necessary
  for(int i = smartlist_len(data[group-1].time_profiles); i < num_buckets; i++)
    smartlist_add(data[group-1].time_profiles, tor_calloc(1, sizeof(int)));

  for(int i = 0; i < num_buckets; i++){
    int* bucket = smartlist_get(data[group-1].time_profiles, i);
    *bucket += *(int*)smartlist_get(stats->time_profile, i);
  }

  /******************** Record Total Cell Counts *******************/

  data[group-1].total_counts[data[group-1].num_circuits] = stats->total_count;

  /************** Record Time Profile Standard Deviations **********/

  // calculate the standard deviation of the time profile
  double stdev = -1;

  //exclude final incomplete window
  int len = smartlist_len(stats->time_profile) -1;

  int sum = 0;
  double mean = 0;
  double diff_squares = 0;

  if(len){
    for(int i = 0; i < len; i++){
      sum += *(int*)smartlist_get(stats->time_profile, i);
    }

    mean = (double)sum / len;

    for(int i = 0; i < len; i++){
      double diff = *(int*)smartlist_get(stats->time_profile, i) - mean;
      diff_squares += diff * diff;
    }

    stdev = sqrt(diff_squares / len);
  }

  data[group-1].time_stdevs[data[group-1].num_circuits] = stdev;

  /*****************************************************************/

  data[group-1].num_circuits++;

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
void mt_stats_publish(void){

  int group = 0;

  // loop through port groups and see if one of them is ready for dumping
  for(int i = 0; i < MT_NUM_PORT_GROUPS; i++){

    // only one port group should be ready to be dumped at a time
    /*tor_assert(group == 0 || data[i].num_circuits < MT_BUCKET_SIZE * MT_BUCKET_NUM);*/

    if(data[i].num_circuits == MT_BUCKET_SIZE * MT_BUCKET_NUM) {
      group = i+1;
      break;
    }
    log_info(LD_GENERAL, "Number of circuit: %d", data[i].num_circuits);
  }

  // if no port groups are ready to be dumped then exit
  if(!group)
    return;

  // create filename based on port group and session number
  const char* group_string = get_port_group_string(group);
  int filename_size = strlen(directory) + strlen(group_string) + strlen(MAX_UINT_STRING) + 3;
  char filename[filename_size];
  memset(filename, '\0', filename_size);
  sprintf(filename, "%s/%s_%d", directory, group_string, session_num[group]++);

  smartlist_t* total_counts_buckets = bucketize_total_counts(&data[group-1].total_counts);
  smartlist_t* time_stdevs_buckets = bucketize_time_stdevs(&data[group-1].time_stdevs);

  mt_publish_to_disk((const char*)filename, data[group-1].time_profiles, total_counts_buckets,
		time_stdevs_buckets);

  // free smartlists
  SMARTLIST_FOREACH_BEGIN(data[group-1].time_profiles, int*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(data[group-1].time_profiles);

  SMARTLIST_FOREACH_BEGIN(total_counts_buckets, double*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(total_counts_buckets);

  SMARTLIST_FOREACH_BEGIN(time_stdevs_buckets, double*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(time_stdevs_buckets);

  // reinitialize global data fields
  data[group-1].time_profiles = smartlist_new();
  data[group-1].num_circuits = 0;
}

/**
 * Returns the general port group to which a given port belongs
 */
int mt_port_group(uint16_t port){

  if(port == 80 || port == 443)
    return MT_PORT_GROUP_WEB;
  if(port < 1000)
    return MT_PORT_GROUP_LOW;

  return MT_PORT_GROUP_OTHER;
}

/**
 * MOCKABLE time for testing purposes
 */
MOCK_IMPL(time_t, mt_time, (void)){
  return approx_time();
}

/**
 * Publishes the given time profiles, total counts, and time stdevs information to
 * the disk. For testing purposes, this can be mockable to intercept the data
 * for validation instead.
 */
MOCK_IMPL(void, mt_publish_to_disk, (const char* filename, smartlist_t* time_profiles_buckets,
			       smartlist_t* total_counts_buckets, smartlist_t* time_stdevs_buckets)){

  smartlist_t* time_profiles_strings = smartlist_new();
  smartlist_t* total_counts_strings = smartlist_new();
  smartlist_t* time_stdevs_strings = smartlist_new();

  for(int i = 0; i < smartlist_len(time_profiles_buckets); i++){
      int time_profile = *(int*)smartlist_get(time_profiles_buckets, i);
      smartlist_add_asprintf(time_profiles_strings, "%d", time_profile);
  }

  for(int i = 0; i < MT_BUCKET_NUM; i++){

    double total_count = *(double*)smartlist_get(total_counts_buckets, i);
    double time_stdev = *(double*)smartlist_get(time_stdevs_buckets, i);

    smartlist_add_asprintf(total_counts_strings, "%lf", total_count);
    smartlist_add_asprintf(time_stdevs_strings, "%lf", time_stdev);
  }

  char* time_profiles_string = smartlist_join_strings(time_profiles_strings, ", ", 0, NULL);
  char* total_counts_string = smartlist_join_strings(total_counts_strings, ", ", 0, NULL);
  char* time_stdevs_string = smartlist_join_strings(time_stdevs_strings, ", ", 0, NULL);

  FILE* fp = fopen(filename, "w");
  fprintf(fp, "%s\n", time_profiles_string);
  fprintf(fp, "%s\n", total_counts_string);
  fprintf(fp, "%s\n", time_stdevs_string);
  fclose(fp);

  SMARTLIST_FOREACH_BEGIN(time_profiles_strings, char*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(time_profiles_strings);

  SMARTLIST_FOREACH_BEGIN(total_counts_strings, char*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(total_counts_strings);

  SMARTLIST_FOREACH_BEGIN(time_stdevs_strings, char*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);
  smartlist_free(time_stdevs_strings);

  // free strings
  tor_free(time_profiles_string);
  tor_free(total_counts_string);
  tor_free(time_stdevs_string);
}

/**
 * Returns a string literal representing a numerical port group
 */
static const char* get_port_group_string(int port_group){

  switch(port_group){
    case MT_PORT_GROUP_OTHER:
      return "port_group_other";
    case MT_PORT_GROUP_WEB:
      return "port_group_web";
    case MT_PORT_GROUP_LOW:
      return "port_group_low";
    case MT_PORT_GROUP_MULTIPLE:
      return "port_group_multiple";
    default:
      return NULL;
  }
}

/**
 * Accepts an array of integers and returns a smartlist of
 * doubles. Conceptionally, original data is sorted and broken up into
 * MT_BUCKET_NUM number sets of MT_BUCKET_SIZE number of elements. The returned
 * valuesare the mean of each bucket
 */
static smartlist_t* bucketize_total_counts(int (*total_counts)[MT_BUCKET_SIZE * MT_BUCKET_NUM]){

  qsort(*total_counts, MT_BUCKET_SIZE * MT_BUCKET_NUM, sizeof(int), int_comp);
  smartlist_t* result = smartlist_new();

  for(int i = 0; i < MT_BUCKET_NUM; i++){
    double sum = 0;
    for(int j = 0; j < MT_BUCKET_SIZE; j++)
      sum += (*total_counts)[i * MT_BUCKET_SIZE + j];

    double* mean = tor_malloc(sizeof(double));
    *mean = sum / MT_BUCKET_SIZE;
    smartlist_add(result, mean);
  }

  return result;
}

/**
 * Accepts an array of doubles and returns a smartlist of
 * doubles. Conceptionally, original data is sorted and broken up into
 * MT_BUCKET_NUM number sets of MT_BUCKET_SIZE number of elements. The returned
 * valuesare the mean of each bucket
 */
static smartlist_t* bucketize_time_stdevs(double (*time_stdevs)[MT_BUCKET_SIZE * MT_BUCKET_NUM]){

  qsort(*time_stdevs, MT_BUCKET_SIZE * MT_BUCKET_NUM, sizeof(double), double_comp);
  smartlist_t* result = smartlist_new();

  for(int i = 0; i < MT_BUCKET_NUM; i++){
    double sum = 0;
    for(int j = 0; j < MT_BUCKET_SIZE; j++)
      sum += (*time_stdevs)[i * MT_BUCKET_SIZE + j];

    double* mean = tor_malloc(sizeof(double));
    *mean = sum / MT_BUCKET_SIZE;
    smartlist_add(result, mean);
  }

  return result;
}

/**
 * Integer comparator function for qsort
 */
static int int_comp(const void* a, const void* b){
  return *(int*)a - *(int*)b;
}

/**
 * Double comparator function for qsort
 */
static int double_comp(const void* a, const void* b){
  double diff = *(double*)a - *(double*)b;
  if(diff > 0)
    return 1;
  if(diff < 0)
    return -1;
  return 0;
}
