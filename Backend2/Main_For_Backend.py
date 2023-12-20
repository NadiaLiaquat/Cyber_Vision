from Backend2.ConvertBytesIntoImage import ConversionBytesIntoImage
from Backend2.ConvertFilesIntoBytes import ConversionFileIntoBytes
from Backend2.SaveFileLocationC import SaveFileLocationC
from Backend2.SaveImageLocationC import SaveImageLocationC
from Backend2.main import AnalysisFile


def conversion_fun():
    _conversionFileIntoBytes = ConversionFileIntoBytes()
    _conversionFileIntoBytes.convertFiles_fun()
    _conversionBytesIntoImage=ConversionBytesIntoImage()
    _conversionBytesIntoImage.bytesIntoImage_fun()


def analysising_Given_file():
    _conversionFileIntoBytes = ConversionFileIntoBytes()
    _conversionFileIntoBytes.convertFiles_fun()
    _conversionBytesIntoImage = ConversionBytesIntoImage()
    _conversionBytesIntoImage.bytesIntoImage_fun()

    saveFileLocationC_object = SaveFileLocationC()
    saveImageLocationC_object = SaveImageLocationC()
    fileLocation = saveFileLocationC_object.getFileLocation()
    imageLocation = saveImageLocationC_object.getImagePath()
    analysisFile_object = AnalysisFile(fileLocation=fileLocation,generatedImage=imageLocation)
    # fileInformation=analysisFile_object.get_MalwareFamily()
    fileInformation=analysisFile_object.checkFile_isMalware()
    return fileInformation

def showMalwareFamilies():
    saveFileLocationC_object = SaveFileLocationC()
    saveImageLocationC_object = SaveImageLocationC()
    fileLocation = saveFileLocationC_object.getFileLocation()
    imageLocation = saveImageLocationC_object.getImagePath()
    analysisFile_object = AnalysisFile(fileLocation=fileLocation, generatedImage=imageLocation)
    malwareFamilyInformation=analysisFile_object.get_MalwareFamily()
    return malwareFamilyInformation

# if __name__ == '__main__':
#     saveFileLocationC = SaveFileLocationC()
#     saveFileLocationC.setFileLocation("E:/Python-Projects/fyp_file4/ming.exe")
#     print(analysising_Given_file())