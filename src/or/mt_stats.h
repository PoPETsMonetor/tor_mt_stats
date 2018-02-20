/**
 * \file mt_stats.h
 * \brief Header file for mt_stats.c
 */

#ifndef MT_STATS_H
#define MT_STATS_H

void mt_stats_init(void);
void mt_stats_circ_create(circuit_t* circ);
void mt_stats_circ_port(circuit_t* circ);
void mt_stats_circ_increment(circuit_t* circ);
void mt_stats_circ_record(circuit_t* circ);
void mt_stats_publish(void);

int mt_port_group(uint16_t port);

#ifdef MT_STATS_PRIVATE
MOCK_DECL(time_t, mt_time, (void));
MOCK_DECL(void, mt_publish_to_disk, (const char* filename, smartlist_t* time_profiles_buckets,
			       smartlist_t* total_counts_buckets, smartlist_t* time_stdevs_buckets));
#endif


#endif
