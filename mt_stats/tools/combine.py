import os
import csv

directory = '../published'

for filename in os.listdir(directory):

    # extract port group from the filename
    group = filename.rsplit('_', 1)[0]

    # read in current aggregate file if it exists
    try:
        with open('../aggregate/' + group, 'rb') as csvfile:
            reader = csv.reader(csvfile, skipiInitialspace=True, delimiter=',');
            aggregateTimeProfiles = [int(x) for x in next(reader)];
            aggregateTotalCounts = [float(x) for x in next(reader)];
            aggregateTimeStdevs = [float(x) for x in next(reader)];
    except IOERROR:
        aggregateTimeProfiles = []
        aggregateTotalCounts = []
        aggregateTimeStdevs = []

    # open each new published file
    with open(directory + '/' + filename, 'rb') as csvfile:
        reader = csv.reader(csvfile, skipInitialspace=True, delimiter=',')
        timeProfiles = [int(x) for x in next(reader)];
        totalCounts = [float(x) for x in next(reader)];
        timeStdevs = [float(x) for x in next(reader)];

    # add new published results to the aggregate
    for i in range(len(aggegateTimeProfiles)):
        aggregateTimeProfiles[i] += timeProfiles[i]
    aggregateTimeProfiles += timeProfiles[len(aggegateTimeProfiles):]
    aggregateTotalCounts += totalCounts
    aggregateTimeStdevs += timeStdevs

    list.sort(aggregateTotalCounts)
    list.sort(aggregateTimeStdevs)

    # delete published file
    os.remove(directory + '/' + filename)

    # overwrite aggregate data
    with open('../aggregate/' + group, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(aggregateTimeProfiles);
        writer.writerow(aggregateTotalCounts);
        writer.writerow(aggregateTimeStdevs);
