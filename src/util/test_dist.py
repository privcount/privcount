import numpy as np
import random
import math
import matplotlib.pyplot as plt

sigma = 240
epochs = 167
random_samples = []
privex_data = []

if __name__ == '__main__':
    sd = sigma/math.sqrt(epochs)
    for i in range(0, 4000):
        random_samples.append(random.gauss(0, sd))
    random_samples.sort()
    sample_cdf_data = np.cumsum(random_samples)

    with open('results_stats.txt', r) as f:
        for line in f:
            if "Other" not in line:
                _, count = line.strip().split()
                privex_data.append(count)
    privex_data.sort()
    privex_cdf = np.cumsum(privex_data)

    plt.plot(sample_cdf_data, privex_cdf)
    plt.ylabel('CDF')
    plt.show()
