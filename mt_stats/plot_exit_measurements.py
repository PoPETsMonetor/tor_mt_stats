import os, sys
import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt
import argparse
import pdb
import csv
import numpy as np

SMALL_SIZE = 12
MEDIUM_SIZE = 14
BIGGER_SIZE = 16

plt.rc('font', size=MEDIUM_SIZE)          # controls default text sizes
plt.rc('axes', titlesize=MEDIUM_SIZE)     # fontsize of the axes title
plt.rc('axes', labelsize=MEDIUM_SIZE)    # fontsize of the x and y labels
plt.rc('xtick', labelsize=BIGGER_SIZE)    # fontsize of the tick labels
plt.rc('ytick', labelsize=MEDIUM_SIZE)    # fontsize of the tick labels
plt.rc('legend', fontsize=BIGGER_SIZE)    # legend fontsize
plt.rc('figure', titlesize=BIGGER_SIZE)  # fontsize of the figure title

parser = argparse.ArgumentParser(description="Plot exit measurements")
parser.add_argument("--dir", help="Directory containing port_group_xxx files")

MT_BUCKET_SIZE = 20

##### Plotting functions #####
# Code cf, getcdf borrowed from pathsim_plot.py written by Aaron Johnson (https://github.com/torps)
## helper - cumulative fraction for y axis
def cf(d): return np.arange(1.0,float(len(d))+1.0)/float(len(d))

## helper - return step-based CDF x and y values
## only show to the 99th percentile by default
def getcdf(data, shownpercentile=0.99):
    data.sort()
    frac = cf(data)
    x, y, lasty = [], [], 0.0
    for i in xrange(int(round(len(data)*shownpercentile))):
        x.append(data[i])
        y.append(lasty)
        x.append(data[i])
        y.append(frac[i])
        lasty = frac[i]
    return (x, y)

if __name__ == "__main__":

    args = parser.parse_args()
    filenames = []

    for root, dirs, files in os.walk(args.dir):
        for filename in files:
            if filename[0] != '.':
                filenames.append(filename)
    fig1 = plt.figure()
    ax1 = fig1.add_subplot(1, 1, 1)
    fig2 = plt.figure()
    ax2 = fig2.add_subplot(1, 1, 1)
    fig3 = plt.figure()
    ax3 = fig3.add_subplot(1, 1, 1)

    legends_fig1, legends_fig2, legends_fig3 = [], [], []
    for filename in filenames:
        with open(args.dir+'/'+filename, 'rb') as csvfile:
            reader = csv.reader(csvfile, skipinitialspace=True, delimiter=',')
            ytimeprofile = [int(x) for x in next(reader)]
            ytotcounts = [float(x) for x in next(reader)]
            ystddevs = [float(x) for x in next(reader)]
        #Todo: improves color, linestyle and y scale (logarithmic?)
        if len(ytimeprofile) > 120:
            ydata = [ytimeprofile[i]/(len(ytotcounts)*MT_BUCKET_SIZE) for i in range(120)]
        else:
            ydata = [ytimeprofile[i]/(len(ytotcounts)*MT_BUCKET_SIZE) for i in range(len(ytimeprofile))]

        ax1.plot([i*5 for i in range(1, len(ydata)+1)], ydata, linewidth=2,\
            label="{0}".format(filename.split('_')[2]))
        if (ytotcounts[-1] > 10000):
            x, y = getcdf(ytotcounts, shownpercentile=0.95)
        else:
            x, y = getcdf(ytotcounts, shownpercentile=1)

        ax2.plot(x, y, linewidth=2,label="{0}".format(filename.split('_')[2]))

        ydata = [x for x in ystddevs if x > 0.0]
        if (ydata[-1] > 2000):
            x, y = getcdf(ydata, shownpercentile=0.95)
        else:
            x, y = getcdf(ydata, shownpercentile=1)
        ax3.plot(x, y, linewidth=2, label="{0}".format(filename.split('_')[2]))

    ax1.set_xlabel('Seconds since the DNS resolve succeeded')
    ax1.set_ylabel('Mean number of cells relayed every 5 seconds')
    labels = []
    for filename in filenames:
        labels.append(filename.split('_')[2])
    # fig1.legend(legends_fig1, labels, loc='upper right')
    ax1.legend(loc='best')
    fig1.savefig('exitmeasurement.png')
    ax2.set_xlabel('Total cell counts')
    ax2.set_ylabel('CDF')
    # fig2.legend(legends_fig2, labels, loc='lower right')
    ax2.legend(loc='best')
    fig2.savefig('totcellcountscdf.png')
    ax3.set_xlabel('Standard deviations in our buckets')
    ax3.set_ylabel('CDF')
    # fig3.legend(legends_fig3, labels, loc='lower right')
    ax3.legend(loc='best')
    fig3.savefig('stddevs.png')


## Todo; figureout what to do with total cells counts and time std


