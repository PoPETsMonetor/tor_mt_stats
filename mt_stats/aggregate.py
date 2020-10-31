import os
import csv

directory = os.path.dirname(os.path.realpath(__file__)) + '/..'

for filename in os.listdir(directory + '/published/'):

    # extract port group from the filename
    group = filename.rsplit('_', 1)[0]

    # read in current aggregate file if it exists
    try:
        with open(directory + '/aggregate/' + group, 'rb') as csvfile:
            reader = csv.reader(csvfile, skipinitialspace=True, delimiter=',');
            aggregateTimeProfiles = [int(x) for x in next(reader)];
            aggregateTotalCounts = [float(x) for x in next(reader)];
            aggregateTimeStdevs = [float(x) for x in next(reader)];
    except IOError:
        aggregateTimeProfiles = []
        aggregateTotalCounts = []
        aggregateTimeStdevs = []

    # open each new published file
    with open(directory + '/published/' + filename, 'rb') as csvfile:
        reader = csv.reader(csvfile, skipinitialspace=True, delimiter=',')
        timeProfiles = [int(x) for x in next(reader)];
        totalCounts = [float(x) for x in next(reader)];
        timeStdevs = [float(x) for x in next(reader)];

    # add new published results to the aggregate
    for i in range(len(aggregateTimeProfiles), len(timeProfiles)):
        aggregateTimeProfiles += [0]
    for i in range(len(timeProfiles)):
        aggregateTimeProfiles[i] += timeProfiles[i]
    aggregateTotalCounts += totalCounts
    aggregateTimeStdevs += timeStdevs

    list.sort(aggregateTotalCounts)
    list.sort(aggregateTimeStdevs)

    # overwrite aggregate data
    with open(directory + '/aggregate/' + group, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(aggregateTimeProfiles);
        writer.writerow(aggregateTotalCounts);
        writer.writerow(aggregateTimeStdevs);
