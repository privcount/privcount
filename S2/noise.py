import numpy
import random
import math
#from exit_weight import *
#from privexUtils import resolution

def Noise(sigma, fingerprint, sum_of_sq, p_exit): 
    random_sample = random.gauss(0,sigma)
    phi = math.sqrt(sigma/sum_of_sq)
    n_raw = phi*p_exit*random_sample
    return n_raw
