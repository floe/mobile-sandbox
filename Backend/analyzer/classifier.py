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
import scipy.sparse
from analyzer.models import *
from classifier_report_loader import *
from classifier_model import *
#########################################################################################
#                                    Functions                                          #
#########################################################################################
class ClassifierOperation():

    def __init__( self, svm_model, threshold = 0.0 ):
        '''
            svm_model: instance of class Model
        '''
        self.__model = svm_model
        self.__threshold = threshold

    def classify( self, report_file ):
        '''
            INPUT:
                report_file: json report of mobile sandbox
            OUTPUT:
                result = { 'is_malicious' : bool,
                        'score' : float,
                        'feature_ranking' : sorted list of tuples }
        '''
        report = ReportLoader( report_file )
        features = report.get_features()
        result = dict()
        result['is_malicious'] = 0
        result['score'] = self.__get_score( features )
        if result['score'] < self.__threshold:
            result['is_malicious'] = 1
        result['feature_ranking'] = self.__get_feature_ranking( features )

        return result

    def set_threshold( self, threshold ):
        '''
            sets classification threshold
        '''
        self.__threshold = threshold

    def __get_score( self, features ):
        '''
            gets a list of app features and returns the svm score
        '''
        w = self.__model.get_weight_vector()
        x = self.__create_app_vector( features )
        score = (w*x)[0,0]
        return score

    def __get_feature_ranking( self, features ):
        pdict = dict()
        for feature in features:
            pdict[feature] = self.__model.get_feature_weight( feature )
        feature_ranking = list()
        for feature, score in sorted( pdict.items(), key=lambda (k,v): (v,k) ):
            feature_ranking.append((feature,score))
        return feature_ranking
    
    def __create_app_vector( self, app_features ):
        M,N = self.__model.get_weight_vector().shape[1],1
        x = scipy.sparse.lil_matrix((M,N), dtype='float32')
        for feature in app_features:
            idx = self.__model.get_dimnr_for_feature( feature )
            if idx > -1: 
                x[idx,0] = 1
        return x

def classify(staticReportFile, sampleId):
    # init classifier
    model_file = '/home/webinterface/analyzer/classifier_data/model/2013-01-19.model'
    dimensions_file = '/home/webinterface/analyzer/classifier_data/model/dimensions.log'
    model = SVMModel( model_file, dimensions_file )
    classifierOp = ClassifierOperation( model )
    classifierOp.set_threshold( -0.1348 )
    # classify apps
    result = classifierOp.classify(staticReportFile)
    (classifiedAppEntry, created) = ClassifiedApp.objects.get_or_create(sample_id=sampleId, score=result['score'], malicious=int(result['is_malicious']))
    for ranking in result['feature_ranking']:
        (classifierEntry, created) = Classifier.objects.get_or_create(sample_id=sampleId, feature=ranking[0], ranking=ranking[1])