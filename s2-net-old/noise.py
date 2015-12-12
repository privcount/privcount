import numpy
import random
import math
from exit_weight import *
from privexUtils import resolution


#def Noise(sensitivity, epsilon, delta, fingerprint, sigma):
def Noise(sigma, fingerprint, sum_of_sq, p_exit):
    sigma_i = p_exit*sigma/math.sqrt(sum_of_sq) 
    random_sample = random.gauss(0,sigma_i)
    return random_sample
#    return 0
