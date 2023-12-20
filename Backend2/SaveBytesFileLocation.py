class SaveBytesFilesLocationC:
    generatedBytesFileLocation = ""

    @staticmethod
    def setBytesPath(bytesPath):
        SaveBytesFilesLocationC.generatedBytesFileLocation = bytesPath

    @staticmethod
    def getBytesPath():
        return SaveBytesFilesLocationC.generatedBytesFileLocation
