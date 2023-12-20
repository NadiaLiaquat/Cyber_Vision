class SaveFileLocationC:
    fileLocation = ""


    @staticmethod
    def setFileLocation(location):
        SaveFileLocationC.fileLocation = location

    @staticmethod
    def getFileLocation():
        return SaveFileLocationC.fileLocation
