#include "math.h"
#include "or.h"
#include "crypto.h"
#include "container.h"
#include "config.h"
#include "mt_stats.h"

#pragma GCC diagnostic ignored "-Wstack-protector"

#define MAX_UINT_STRING "4294967295"

// general use parameters used to define scale in the bucketing funciton
#define COUNT_PARAM 100
#define STDEV_PARAM 100

/**
 * Track one set of data for each of these port groups
 */
typedef enum {
  PORT_GROUP_WEB,
  PORT_GROUP_LOW,
  PORT_GROUP_OTHER,
} port_group_t;

/**
 * Data tracked for each port groups. Each smartlist records pointers to an
 * entry_t struct
 */
typedef struct {
  smartlist_t* total_counts;
  smartlist_t* time_profiles;
  smartlist_t* time_stdevs;
} data_t;

/**
 * Single entry in a data set. The sum and count are recorded so that the data
 * can be dumped in the form of a mean at the end.
 */
typedef struct {
  double sum;
  uint32_t count;
} entry_t;

// helper functions
static port_group_t get_port_group(uint16_t port);
static int get_count_bucket(int count);
static int get_stdev_bucket(int stdev);

// global data that will eventually be dumped to disk
static digestmap_t* global_data;

// index of the next session of data to be dumped to disk
static int session;
static time_t prev;
static const char* mt_directory = "moneTor_live_data";

static port_group_t groups[] = {PORT_GROUP_WEB, PORT_GROUP_LOW, PORT_GROUP_OTHER};

/**
 * Globally initialize the mt_stats module. Should only be called once outside
 * of the module.
 */
void mt_stats_init(void){

  global_data = digestmap_new();

  for(int i = 0; i < sizeof(groups) / sizeof(port_group_t); i++){
    char digest[DIGEST_LEN] = {0};
    memcpy(digest, groups[i], sizeof(port_group_t));

    data_t* data = tor_malloc(sizeof(data_t));
    data.total_counts = smartlist_new();
    data.time_profiles = smarlitst_new();
    data.time_stdevs = smartlist_new();

    digestmap_add(global_data, digest_web, stat);
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

  log_info(LD_GENERAL, "mt_stats %u", TO_OR_CIRCUIT(circ)->p_circ_id);
  stats->collecting = 1;
  stats->port = 0;
  stats->start_time = mt_time();
  stats->time_profiles = smartlist_new();

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
    /** make sure there is only one port in use and record it */
    //tor_assert(or_circ->n_streams && !or_circ->n_streams->next_stream);
    connection_t* stream = TO_CONN(or_circ->n_streams);
    if(stats->port && stats->port != stream->port)
      stats->is_multiport = 1;
    stats->port = stream->port;
    log_info(LD_GENERAL, "mt_stats %u %u", or_circ->p_circ_id, stream->port);
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

/**
 * At the end of a circuit's lifetime, record the mt_stats data to the global
 * record
 */
void mt_stats_circ_record(circuit_t* circ){

  // exit if the circuit is not marked for stat collection
  if(CIRCUIT_IS_ORIGIN(circ) || !TO_OR_CIRCUIT(circ)->mt_stats.collecting)
    return;

  // if the port was never set then the exit stream was never used
  if(!TO_OR_CIRCUIT(circ)->mt_stats.port){
    stats->collecting = 0;
    smartlist_free(stats->time_profiles);
    return;
  }

  mt_stats_t* stats = &TO_OR_CIRCUIT(circ)->mt_stats;

  // obtain global data for the right port group
  port_group_t group = get_port_group(stats->port);
  char digest[DIGEST_LEN] = {0};
  memcpu(digest, group; sizeof(port_group_t));
  data_t* data = digestmap_get(global_data, digest);

  /******************** Record Total Cell Counts *******************/

  int count_index = get_count_bucket(stats->total_cells);

  // populate global cell count buckets in necessary
  for(int i = smartlist_len(data->total_cells); i <= count_index; i++)
    smartlist_add(data->total_cells, tor_calloc(1, sizeof(int)));

  *smartlist_get(data->total_cells, count_index)++;

  /*********************** Record Time Profiles ********************/

  // increment global time profiles
  for(int i = 0; i < smartlist_len(stats->time_profiles); i++){

    entry_t* stat;

    // retrieve the appropriate item from the list or add one if non exists
    if(i < smartlist_len(data->time_profiles)){
      stat = smartlist_get(data->time_profiles, i);
    }
    else {
      stat = tor_calloc(1, sizeof(entry_t));
      smartlist_add(data->time_profiles, stat);
    }

    stat->sum += *smartlist_get(stats->time_profiles, i);
    stat->count++;
  }

  /************** Record Time Profile Standard Deviations **********/

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

  int stdev_index = get_stdev_bucket(stdev);

  // populate global cell count buckets in necessary
  for(int i = smartlist_len(data->time_stdevs); i <= stdev_index; i++)
    smartlist_add(data->time_stdevs, tor_calloc(1, sizeof(int)));

  *smartlist_get(data->time_stdevs, stdev_index)++;

  /*****************************************************************/

  // free circ time_profile items
  SMARTLIST_FOREACH_BEGIN(stats, entry_t*, cp) {
    tor_free(cp);
  } SMARTLIST_FOREACH_END(cp);

  // free circ time_profile
  smartlist_free(stats->time_profiles);
}

/**
 * Dump the global statistics collection data, clear the memory, and prepare for
 * the next session
 */
void mt_stats_dump(void){

  time_t now = mt_time();

  // do this every hour
  if(localtime(&now)->tm_yday > localtime(&prev)->tm_yday){

    // define filename based on time
    char filename[strlen(mt_directory) + strlen(MAX_UINT_STR) + 1] = {0};
    memcpy(filename, mt_directory, strlen(mt_directory));
    sprintf(filename + strlen(mt_directory), "_%03d", session++);

    for(int i = 0; i < sizeof(groups) / sizeof(port_group_t); i++){

      char digest[DIGESt_LEN] = {0};
      memcpu(digest, groups[i]; sizeof(port_group_t));

      data_t* data = digestmap_get(global_data, digest);

      // write port as ascii
      char port_string[strlen(MAX_UINT_STR) + 1] = {0};
      sprintf(port_string, "port group: %u", groups[i]);

      char* total_counts_string = smartlist_join_strings(data->total_counts, ", ", 0, NULL);
      char* time_profiles_string = smartlist_join_strings(data->time_profiles, ", ", 0, NULL);
      char* time_stdevs_string = smartlist_join_strings(data->time_stdevs, ", ", 0, NULL);

      FILE* fp = fopen(filename, "a");
      fprintf(fp, "%s\n", port_string);
      fprintf(fp, "%s\n", total_counts_string);
      fprintf(fp, "%s\n", time_profiles_string);
      fprintf(fp, "%s\n", time_stdevs_string);
      fclose(fp);

      // free strings
      tor_free(total_counts_strings);
      tor_free(time_profiles_strings);
      tor_free(time_stdevs_strings);

      // free smartlist elements
      SMARTLIST_FOREACH_BEGIN(data->total_cell_counts, entry_t*, cp) {
	tor_free(cp);
      } SMARTLIST_FOREACH_END(cp);
      SMARTLIST_FOREACH_BEGIN(data->time_profiles, entry_t*, cp) {
	tor_free(cp);
      } SMARTLIST_FOREACH_END(cp);
      SMARTLIST_FOREACH_BEGIN(data->time_stdevs, entry_t*, cp) {
	tor_free(cp);
      } SMARTLIST_FOREACH_END(cp);

      // free smartlists
      smartlist_free(data->total_counts);
      smartlist_free(data->time_profiles);
      smartlist_free(data->time_stdevs);

      // reinitialize smartlists
      data->total_count = smartlist_new();
      data->time_profiles = smartlist_new();
      data->time_deviaitons = smartlist_new();

      prev = now;
    }

    // reset global data
    digestmap_free(global_data);
    mt_stats_init();
  }
}

MOCK_IMPL(time_t, mt_time, (void)){
  return approx_time();
}

static port_group_t get_port_group(uint16_t port){
  if(port == 80 || port == 443)
    return PORT_GROUP_WEB;
  if(port < 1000)
    return PORT_GROUP_LOW;

  return PORT_GROUP_OTHER;
}

static int get_count_bucket(int count, int param){
  return count / COUNT_PARAM;
}
static int get_stdev_bucket(int stdev, double param){
  return (int)(stdev / STDEV_PARAM);
}
