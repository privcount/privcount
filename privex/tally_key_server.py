'''
Created on Dec 12, 2015

@author: rob
'''
from threading import Thread

class TallyKeyServerManager(Thread):

    def __init__(self, config_file):
        super(TallyKeyServerManager, self).__init__()
        self.config_file = config_file

    def run(self):
        pass