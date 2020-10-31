# Basic simulator to calculate relative bandwidth effects of varying the
# moneoTor priority scale and the number of premium/nonpremium users. The
# simulator very basically assumes a fixed number of cells related every time
# step and that all clients are bulk clients. The only determinant of bandwidth
# is the scheduling algorithm.
#
# args:
#    param1 (float): MT_PRIORITY_SCALE -- between 0 and 1
#    param2 (int): number of non-premium(regular) circuits
#    param3(int): number of premium circuits
#
# output:
#    cells related by each labeled circuit
#    fraction of regular circuit bandwidth to premium circuit bandwidths

import sys

priority = float(sys.argv[1]);
numNonPrem = int(sys.argv[2]);
numPremium = int(sys.argv[3]);

iterations = 10000;
constant = 0.5
cellsPerRound = 1;
timePerRound = 0.001;

scores = [0] * (numNonPrem + numPremium);
relayed = [0] * (numNonPrem + numPremium);

# if scores are equal then relay both
for i in range(iterations):
    circuit = scores.index(min(scores))
    modifier = priority if circuit >= numNonPrem else 1.0
    scores[circuit] += cellsPerRound * constant**(-i * timePerRound) / modifier
    relayed[circuit] += cellsPerRound

sumNonPrem = 0
for i in range(numNonPrem):
    sumNonPrem += relayed[i]

sumPremium = 0
for i in range(numNonPrem, numNonPrem + numPremium):
    sumPremium += relayed[i]

meanRelayed = float(iterations * cellsPerRound) / (numNonPrem + numPremium)
meanNonPrem = float(sumNonPrem) / numNonPrem
meanPremium = float(sumPremium) / numPremium
nonPremAdvantage = meanPremium / meanNonPrem
vanillaAdvantage = meanPremium / meanRelayed

print "Mean Total Relayed: " + str(meanRelayed)
print "Mean NonPrem Relayed: " + str(meanNonPrem)
print "Mean Premium Relayed: " + str(meanPremium)

print "Premium -> Vanilla Advantage: " + str(vanillaAdvantage * 100) + "%"
print "Premium -> NonPrem Advantage: " + str(nonPremAdvantage * 100) + "%"
