/**
 * \file mt_stats.h
 * \brief Header file for mt_stats.c
 */

#ifndef MT_STATS_H
#define MT_STATS_H

void mt_stats_init(void);
void mt_stats_circ_create(circuit_t* circ);
void mt_stats_circ_init(circuit_t* circ);
void mt_stats_circ_increment(circuit_t* circ);
void mt_stats_circ_record(circuit_t* circ);
void mt_stats_dump(void);

MOCK_DECL(time_t, mt_time, (void));

#endif
