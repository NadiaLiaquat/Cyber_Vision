import os
import uuid
import os

from Backend2.SaveBytesFileLocation import SaveBytesFilesLocationC
from Backend2.SaveFileLocationC import SaveFileLocationC
from Backend2.SaveImageLocationC import SaveImageLocationC


class ConversionFileIntoBytes:

    def get_file_binaries(self,file_path):
        with open(file_path, 'rb') as f:
            content = f.read()
        return content

    def write_binaries_to_bytes(self,binaries, file_path):
        with open(file_path, 'wb') as f:
            f.write(binaries)

    def convertFiles_fun(self):
        try:
            saveFilesLocation = SaveFileLocationC()
            filePath = saveFilesLocation.getFileLocation()
            binaries = self.get_file_binaries(file_path=filePath)
            random_file_name = str(uuid.uuid4())

            # bytes_file_path = f'E:\Python-Projects\Front_end\Backend2\GenertedBytesFiles\{random_file_name}.bytes'
            os.makedirs('Front_end/Backend2/GenertedBytesFiles', exist_ok=True)

            # Now, try to create the file
            bytes_file_path = f'Front_end/Backend2/GenertedBytesFiles/{random_file_name}.bytes'

            self.write_binaries_to_bytes(binaries, bytes_file_path)
            bytes_saver = SaveBytesFilesLocationC()

            # Set the generated image path in the SaveImageLocationC class
            bytes_saver.setBytesPath(bytes_file_path)
            print("Files Is Successfully Converted into bytes")
        except Exception as e:
            print(f"Here is error t {str(e)}")

# if __name__ == '__main__':
#     saveFileLocationC = SaveFileLocationC()
#     saveFileLocationC.setFileLocation("E:/Python-Projects/fyp_file4/ming.exe")
#     obj= ConversionFileIntoBytes()
#     obj.convertFiles_fun()
