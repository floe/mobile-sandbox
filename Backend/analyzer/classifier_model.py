#!/usr/bin/env python
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2013, Mobile-Sandbox
# Daniel Arp (daniel.arp@informatik.uni-goettingen.de)
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#########################################################################################
#                          Imports  & Global Variables                                  #
#########################################################################################
import numpy as np
import scipy.sparse
#########################################################################################
#                                    Functions                                          #
#########################################################################################
class SVMModel():

    def __init__( self, model_file, dim_file ):
        self.__model_file = model_file
        self.__dim_file = dim_file
        self.__weights = self.__load_weights()
        # get matching feature <-> idx
        self.__feature2dimnr = dict()
        self.__dimnr2feature = dict()
        self.__load_features()

    def get_weight_vector( self ):
        '''
            returns sparse numpy matrix which contains model weights
        '''
        return self.__weights

    def get_feature_weight( self, feature ):
        '''
            returns weight for certain feature 
        '''
        score = 0.0
        if feature in self.__feature2dimnr:
            idx = self.__feature2dimnr[feature]
            score = self.__weights[0,idx]
        return score

    def get_dimnr_for_feature( self, feature ):
        '''
            returns index of dimension in weight vector 
            for certain feature
        '''
        idx = -1
        if feature in self.__feature2dimnr:
            idx = self.__feature2dimnr[feature]
        return idx

    def get_feature_for_dimnr( self, dimnr ):
        '''
            returns feature for certain index of dimension
            in weight vector
        '''
        feature = ''
        if dimnr in self.__dimnr2feature:
            feature = self.__dimnr2feature[dimnr]
        return feature

    def __load_features( self ):
        features = dict()
        lines = open(self.__dim_file,'rb').readlines()

        # get indices unequal zero
        indices = np.where(self.__weights.toarray() != 0)[1]
        for idx in indices:
            line = lines[idx]
            feature = line[0:len(line)-1]
            self.__feature2dimnr[feature] = idx
            self.__dimnr2feature[idx] = feature

    def __load_weights( self ):
        lines = open(self.__model_file,'rb').readlines()
        start_reading = False
        w = list()
        for line in lines:
            val = line.strip()
            
            if start_reading:
                w.append(val)

            if val == 'w':
                start_reading = True
        w = np.array(w,dtype='float32')
        return scipy.sparse.csr_matrix(w)