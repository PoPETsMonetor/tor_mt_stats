import os, sys
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.pyplot as plt
import argparse
import pdb
import csv


SMALL_SIZE = 12
MEDIUM_SIZE = 14
BIGGER_SIZE = 16

plt.rc('font', size=SMALL_SIZE)          # controls default text sizes
plt.rc('axes', titlesize=SMALL_SIZE)     # fontsize of the axes title
plt.rc('axes', labelsize=MEDIUM_SIZE)    # fontsize of the x and y labels
plt.rc('xtick', labelsize=MEDIUM_SIZE)    # fontsize of the tick labels
plt.rc('ytick', labelsize=MEDIUM_SIZE)    # fontsize of the tick labels
plt.rc('legend', fontsize=SMALL_SIZE)    # legend fontsize
plt.rc('figure', titlesize=BIGGER_SIZE)  # fontsize of the figure title

parser = argparse.ArgumentParser(description="Plot ou payment rate possibilities, compared to latency")
parser.add_argument("--csvfile", help="path to Csv file with real Tor bandwidth measurements")
parser.add_argument("--dsize", type=int, default=5242880, help="Size of the file matching the timing from --csvfile, in Bytes")

CELL_TOT_SIZE = 514 #bytes
CELL_PAYLOAD_SIZE = 509 #bytes
CELL_OVERHEAD = float(CELL_TOT_SIZE)/CELL_PAYLOAD_SIZE
TLS_OVERHEAD = 1.07 #7% overhead on data sent ~ observed on a few Tor relays;

def bw_to_cells_per_second(time_to_dl_dsize, dsize):
    """
        gives a number of cells per second for a bw, taking in account
        the real CELL_TOT_SIZE and CELL_PAYLOAD and the TLS OVERHEAD
        
        - time_to_dl_dsize expected in seconds
        - dsize expected in bytes
    """
    return ((float(dsize)*CELL_OVERHEAD*TLS_OVERHEAD)/CELL_PAYLOAD_SIZE)/time_to_dl_dsize


if __name__ == "__main__":
    
    args = parser.parse_args()
    minfstquartile = 1000 #arbitrary high
    maxlastquartile = 0
    median = []
    with open(args.csvfile, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        next(reader) #skip header
        for row in reader:
            if float(row[1]) < minfstquartile:
                minfstquartile = float(row[1])
            median.append(float(row[2]))
            if float(row[3]) > maxlastquartile:
                maxlastquartile = float(row[3])
    median = median[len(median)/2]
    fig = plt.figure()
    x = range(30, 250)
    plt.plot(x, [bw_to_cells_per_second(maxlastquartile, args.dsize)*(i/1000.0) for i in x], linewidth=2)
    plt.plot(x, [bw_to_cells_per_second(median, args.dsize)*(i/1000.0) for i in x], linewidth=2)
    plt.plot(x, [bw_to_cells_per_second(minfstquartile, args.dsize)*(i/1000.0) for i in x], linewidth=2)
    plt.xlabel('Payment latency [ms]')
    plt.ylabel('Lower bound for cells payment rate [cells/payments]')
    plt.legend(['Min bandwidth observed', 'Median bandwidth observed', 'Max bandwidth observed'], loc="best")
    plt.savefig("paymentrate.png")

    

