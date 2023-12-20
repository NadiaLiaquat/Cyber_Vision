class SaveImageLocationC:
    generatedImageLocation = ""


    @staticmethod
    def setImagePath(imagePath):
        SaveImageLocationC.generatedImageLocation = imagePath

    @staticmethod
    def getImagePath():
        return SaveImageLocationC.generatedImageLocation
