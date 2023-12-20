import os
import numpy as np
import tensorflow as tf
# import tensorflow.keras as keras
from keras.models import load_model
import keras.utils as image
from PIL import ImageFile
from Backend2.ConfirmModelPrediction import ConfirmPredition
from Backend2.MalwareFemily import MalwareFamilies
from Backend2.Malware_DetectionCNN import MalwareDetectionCNN
from Backend2.Malware_DetectionResNet import MalwareDetectionResNet

ImageFile.LOAD_TRUNCATED_IMAGES = True


class AnalysisFile:
    def __init__(self, fileLocation, generatedImage):
        self.fileLocation = fileLocation
        self.generatedImage = generatedImage

    def processFile(self):
        malwareDetectionCNN_obj = MalwareDetectionCNN(imagePath=self.generatedImage)
        fileStatus_From_CNN, confidence_From_CNN = malwareDetectionCNN_obj.detectMalware_CNN()
        malwareDetectionResNet_obj = MalwareDetectionResNet(imagePath=self.generatedImage)
        fileStatus_From_ResNet, confidence_From_ResNet = malwareDetectionResNet_obj.detectMalware_ResNet()
        file_Status_Dictionary = {'FileStatus_From_CNN': fileStatus_From_CNN,
                                  'Confidence_From_CNN': confidence_From_CNN,
                                  'FileStatus_From_ResNet': fileStatus_From_ResNet,
                                  'Confidence_From_ResNet': confidence_From_ResNet
                                  }
        return file_Status_Dictionary

    def checkFile_isMalware(self):
        file_Status_Dictionary = self.processFile()

        if int(file_Status_Dictionary.get('Confidence_From_CNN')) >= 50 and int(
                file_Status_Dictionary.get('Confidence_From_ResNet')) >= 50:
            confirmPredition_obj = ConfirmPredition(fileName=self.fileLocation)
            information = confirmPredition_obj.verifyPredictions()
            if information == "Not Malware":
                return "Not Malware"
            else:
                print("Verified")
                return file_Status_Dictionary
        else:
            print(f"CheckFile_isMalware")
            return False

    def get_MalwareFamily(self):
        malwareFamily_obj = MalwareFamilies(self.fileLocation, self.generatedImage)
        fileInformationWithFamily = malwareFamily_obj.malwareFamily_Recogization()
        print(f" Malware Family Type Is Dictionary   {isinstance(fileInformationWithFamily, dict)}")
        print(f" Malware Family Type Is List   {isinstance(fileInformationWithFamily, dict)}")
        print(f" Malware Family Type Is    {type(fileInformationWithFamily)}")
        if isinstance(fileInformationWithFamily, dict):
            return fileInformationWithFamily
        elif isinstance(fileInformationWithFamily, list):
            print("Malware Family is In List")
            return fileInformationWithFamily
        elif fileInformationWithFamily == False:

            return False  # unable to detect Malware Femily

# if __name__ == '__main__':
#     obj = AnalysisFile(fileLocation="E:\Python-Projects\MachineLearning\Malware_DetectionCNN.py",
#                        generatedImage="E:\Python-Projects\MachineLearning\Models\ModelsForFemilies\Images\\tr1.png")
#     check = obj.get_MalwareFamily()
#
#
#     print(f"File Info is {check}")
