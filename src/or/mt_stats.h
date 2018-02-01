/**
 * \file mt_stats.h
 * \brief Header file for mt_stats.c
 */

#ifndef MT_STATS_H
#define MT_STATS_H

void mt_stats_init(circuit_t* circ);
void mt_stats_increment(circuit_t* circ);
void mt_stats_record(circuit_t* circ);

MOCK_DECL(time_t, mt_time, (void));

#endif
